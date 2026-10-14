function ConvertFrom-CertToolboxSignedStructure {
    <#
    .SYNOPSIS
        Splits a signed DER structure into the bytes that were signed, the signature algorithm
        and the signature.
    .DESCRIPTION
        A certificate, a CRL and a basic OCSP response share one shape:
        SEQUENCE { toBeSigned, signatureAlgorithm, signature BIT STRING, ... }. The signature
        covers the first element exactly as encoded, header included, so that element is
        returned as the bytes found in the input, never re-encoded.
    .PARAMETER Bytes
        The data containing the structure.
    .PARAMETER Offset
        Index of the structure's first byte. Zero for a certificate or a CRL; a basic OCSP
        response sits inside a larger response.
    .OUTPUTS
        PSCustomObject with ToBeSigned (bytes), AlgorithmOid (the algorithm's object identifier
        as dash-separated hex bytes), Signature (bytes) and Part (the headers of the
        structure's elements, for callers that need a further one).
    .EXAMPLE
        ConvertFrom-CertToolboxSignedStructure -Bytes $certificate.RawData
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes,

        [Parameter()]
        [int] $Offset = 0
    )

    $outer = Read-CertToolboxDerHeader -Bytes $Bytes -Offset $Offset
    if (-not $outer -or $outer.Tag -ne 0x30) {
        throw [System.FormatException]::new('The data is not a signed DER structure.')
    }
    $part = @(Get-CertToolboxDerChild -Bytes $Bytes -Parent $outer)
    if ($part.Count -lt 3 -or $part[1].Tag -ne 0x30 -or $part[2].Tag -ne 0x03 -or $part[2].Length -lt 1) {
        throw [System.FormatException]::new('The signed DER structure lacks its algorithm or its signature.')
    }

    $algorithm = @(Get-CertToolboxDerChild -Bytes $Bytes -Parent $part[1])
    if ($algorithm.Count -lt 1 -or $algorithm[0].Tag -ne 0x06) {
        throw [System.FormatException]::new('The signature algorithm of the DER structure cannot be read.')
    }

    [PSCustomObject]@{
        ToBeSigned   = Copy-CertToolboxByteRange -Bytes $Bytes -Offset $part[0].Offset -Length ($part[0].ValueOffset + $part[0].Length - $part[0].Offset)
        AlgorithmOid = [System.BitConverter]::ToString($Bytes, $algorithm[0].ValueOffset, $algorithm[0].Length)
        # The first byte of a BIT STRING counts its unused bits; the signature follows it.
        Signature    = Copy-CertToolboxByteRange -Bytes $Bytes -Offset ($part[2].ValueOffset + 1) -Length ($part[2].Length - 1)
        Part         = $part
    }
}

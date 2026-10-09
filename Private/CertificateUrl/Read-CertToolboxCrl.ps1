function Read-CertToolboxCrl {
    <#
    .SYNOPSIS
        Reads the dates of a certificate revocation list and tells whether a serial number is
        listed in it.
    .DESCRIPTION
        Decodes the CRL by hand (RFC 5280, section 5.1): the full framework has no CRL reader.
        Accepts DER, and the PEM form some CAs publish.

        The list of revoked certificates is scanned in a single inline loop over the bytes: a
        CRL can hold tens of thousands of entries, and creating an object per entry would take
        seconds instead of milliseconds.

        The CRL's signature is not verified, and neither is its issuer or its scope (a
        partitioned or delta CRL is read like a full one): this reads what the file says.
    .PARAMETER Bytes
        The CRL as downloaded.
    .PARAMETER SerialNumber
        The certificate serial number to look for, most significant byte first.
    .OUTPUTS
        PSCustomObject with ThisUpdate, NextUpdate ($null when the CRL has none), EntryCount and
        SerialListed.
    .EXAMPLE
        Read-CertToolboxCrl -Bytes $crlBytes -SerialNumber $serial
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes,

        [Parameter(Mandatory)]
        [byte[]] $SerialNumber
    )

    if ($Bytes.Length -gt 0 -and $Bytes[0] -eq 0x2D) {
        $text = [System.Text.Encoding]::ASCII.GetString($Bytes)
        if ($text -notmatch '-----BEGIN X509 CRL-----(?<body>[^-]+)-----END X509 CRL-----') {
            throw [System.FormatException]::new('The data is neither a DER nor a PEM certificate revocation list.')
        }
        $Bytes = [System.Convert]::FromBase64String(($Matches['body'] -replace '\s', ''))
    }

    $outer = Read-CertToolboxDerHeader -Bytes $Bytes -Offset 0
    if (-not $outer -or $outer.Tag -ne 0x30) {
        throw [System.FormatException]::new('The data is not a certificate revocation list.')
    }
    $tbs = @(Get-CertToolboxDerChild -Bytes $Bytes -Parent $outer)[0]
    $field = @(Get-CertToolboxDerChild -Bytes $Bytes -Parent $tbs)

    # TBSCertList ::= SEQUENCE { version INTEGER OPTIONAL, signature, issuer, thisUpdate,
    #   nextUpdate OPTIONAL, revokedCertificates SEQUENCE OPTIONAL, crlExtensions [0] OPTIONAL }
    $index = 0
    if ($field[0].Tag -eq 0x02) {
        $index = 1
    }
    if ($field.Count -lt $index + 3) {
        throw [System.FormatException]::new('The certificate revocation list is truncated.')
    }

    $thisUpdate = ConvertFrom-CertToolboxDerTime -Bytes $Bytes -Header $field[$index + 2]
    $nextUpdate = $null
    $index += 3
    if ($index -lt $field.Count -and ($field[$index].Tag -eq 0x17 -or $field[$index].Tag -eq 0x18)) {
        $nextUpdate = ConvertFrom-CertToolboxDerTime -Bytes $Bytes -Header $field[$index]
        $index++
    }

    # Leading zero bytes are not significant: a serial is compared as a number.
    $wantedStart = 0
    while ($wantedStart -lt $SerialNumber.Length - 1 -and $SerialNumber[$wantedStart] -eq 0) {
        $wantedStart++
    }
    $wantedLength = $SerialNumber.Length - $wantedStart

    $entryCount = 0
    $serialListed = $false
    if ($index -lt $field.Count -and $field[$index].Tag -eq 0x30) {
        $offset = $field[$index].ValueOffset
        $end = $offset + $field[$index].Length

        while ($offset + 4 -le $end) {
            # Entry header: SEQUENCE tag, then its length.
            $first = $Bytes[$offset + 1]
            $valueOffset = $offset + 2
            $length = [int]$first
            if ($first -ge 0x80) {
                $lengthByteCount = $first -band 0x7F
                $length = 0
                for ($i = 0; $i -lt $lengthByteCount; $i++) {
                    $length = ($length * 256) + $Bytes[$valueOffset + $i]
                }
                $valueOffset += $lengthByteCount
            }

            # First field of the entry: the serial, an INTEGER with a short-form length.
            $serialLength = [int]$Bytes[$valueOffset + 1]
            $serialOffset = $valueOffset + 2
            while ($serialLength -gt 1 -and $Bytes[$serialOffset] -eq 0) {
                $serialOffset++
                $serialLength--
            }

            if (-not $serialListed -and $serialLength -eq $wantedLength) {
                $same = $true
                for ($i = 0; $i -lt $serialLength; $i++) {
                    if ($Bytes[$serialOffset + $i] -ne $SerialNumber[$wantedStart + $i]) {
                        $same = $false
                        break
                    }
                }
                if ($same) {
                    $serialListed = $true
                }
            }

            $entryCount++
            $offset = $valueOffset + $length
        }
    }

    [PSCustomObject]@{
        ThisUpdate   = $thisUpdate
        NextUpdate   = $nextUpdate
        EntryCount   = $entryCount
        SerialListed = $serialListed
    }
}

function Copy-CertToolboxByteRange {
    <#
    .SYNOPSIS
        Returns a copy of part of a byte array.
    .DESCRIPTION
        Used to take a whole DER element, header included, out of a larger structure: the bytes
        a signature covers are exactly the encoded element, so they have to be extracted as
        they are, not re-encoded.
    .PARAMETER Bytes
        The source data.
    .PARAMETER Offset
        Index of the first byte to copy.
    .PARAMETER Length
        Number of bytes to copy.
    .OUTPUTS
        System.Byte[]
    .EXAMPLE
        Copy-CertToolboxByteRange -Bytes $bytes -Offset $header.Offset -Length ($header.ValueOffset + $header.Length - $header.Offset)
    #>
    [CmdletBinding()]
    [OutputType([byte[]], [System.Array])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes,

        [Parameter(Mandatory)]
        [int] $Offset,

        [Parameter(Mandatory)]
        [int] $Length
    )

    if ($Offset -lt 0 -or $Length -lt 0 -or $Offset + $Length -gt $Bytes.Length) {
        throw [System.FormatException]::new('A DER element extends past the end of the data.')
    }

    $result = New-Object byte[] $Length
    [System.Array]::Copy($Bytes, $Offset, $result, 0, $Length)
    , $result
}

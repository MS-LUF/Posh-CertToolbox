function Read-CertToolboxDerHeader {
    <#
    .SYNOPSIS
        Reads one DER tag-and-length header from a byte array.
    .DESCRIPTION
        Minimal DER reader, enough to walk a certificate extension: single-byte tags only, and
        definite lengths in short form (one byte below 0x80) or long form (0x80 + n followed by
        n big-endian length bytes).
    .PARAMETER Bytes
        The DER-encoded data.
    .PARAMETER Offset
        Index of the tag byte to read.
    .OUTPUTS
        PSCustomObject with Offset (index of the tag byte), Tag, Length and ValueOffset (index
        of the first value byte), or nothing when the header runs past the end of the data.
    .EXAMPLE
        Read-CertToolboxDerHeader -Bytes $extension.RawData -Offset 0
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes,

        [Parameter(Mandatory)]
        [int] $Offset
    )

    if ($Offset + 1 -ge $Bytes.Length) {
        return
    }

    $tag = $Bytes[$Offset]
    $first = $Bytes[$Offset + 1]
    $valueOffset = $Offset + 2
    $length = [int]$first

    if ($first -ge 0x80) {
        $lengthByteCount = $first -band 0x7F
        if ($lengthByteCount -eq 0 -or $lengthByteCount -gt 4 -or $valueOffset + $lengthByteCount -gt $Bytes.Length) {
            return
        }
        $length = 0
        for ($i = 0; $i -lt $lengthByteCount; $i++) {
            $length = ($length * 256) + $Bytes[$valueOffset + $i]
        }
        $valueOffset += $lengthByteCount
    }

    [PSCustomObject]@{
        Offset      = [int]$Offset
        Tag         = [int]$tag
        Length      = [int]$length
        ValueOffset = [int]$valueOffset
    }
}

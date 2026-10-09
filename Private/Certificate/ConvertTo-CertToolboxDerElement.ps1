function ConvertTo-CertToolboxDerElement {
    <#
    .SYNOPSIS
        Encodes one DER element from a tag and its content.
    .DESCRIPTION
        Prepends the tag and the definite length (short form below 128 bytes, long form above)
        to the content. Nesting calls builds a structure from the inside out, which is all an
        OCSP request needs.
    .PARAMETER Tag
        The tag byte, for instance 0x30 for a SEQUENCE or 0x04 for an OCTET STRING.
    .PARAMETER Content
        The already-encoded content of the element. May be empty.
    .OUTPUTS
        System.Byte[]
    .EXAMPLE
        ConvertTo-CertToolboxDerElement -Tag 0x04 -Content $hash
    #>
    [CmdletBinding()]
    [OutputType([byte[]], [System.Array])]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(0, 255)]
        [int] $Tag,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]] $Content
    )

    $length = $Content.Length
    if ($length -lt 0x80) {
        $lengthBytes = [byte[]]@($length)
    } elseif ($length -lt 0x100) {
        $lengthBytes = [byte[]]@(0x81, $length)
    } elseif ($length -lt 0x10000) {
        $lengthBytes = [byte[]]@(0x82, ($length -shr 8), ($length -band 0xFF))
    } else {
        $lengthBytes = [byte[]]@(0x83, ($length -shr 16), (($length -shr 8) -band 0xFF), ($length -band 0xFF))
    }

    $result = New-Object byte[] (1 + $lengthBytes.Length + $length)
    $result[0] = [byte]$Tag
    [System.Array]::Copy($lengthBytes, 0, $result, 1, $lengthBytes.Length)
    [System.Array]::Copy($Content, 0, $result, 1 + $lengthBytes.Length, $length)

    # The unary comma keeps the array whole: without it PowerShell would emit it byte by byte.
    , $result
}

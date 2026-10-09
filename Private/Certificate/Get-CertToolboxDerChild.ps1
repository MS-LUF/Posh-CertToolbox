function Get-CertToolboxDerChild {
    <#
    .SYNOPSIS
        Returns the headers of the elements directly contained in a DER element.
    .DESCRIPTION
        Walks the value of a constructed element (a SEQUENCE, a SET or an explicit tag) and
        returns one header per child, in order. Throws when a child does not fit inside its
        parent, which means the data is not well-formed DER.

        Meant for structures with a handful of children. Do not use it to walk the entries of a
        large list such as the revoked certificates of a CRL: one object per entry is far too
        slow there.
    .PARAMETER Bytes
        The DER-encoded data.
    .PARAMETER Parent
        The header of the containing element, as returned by Read-CertToolboxDerHeader.
    .OUTPUTS
        PSCustomObject, one Read-CertToolboxDerHeader result per child.
    .EXAMPLE
        Get-CertToolboxDerChild -Bytes $bytes -Parent (Read-CertToolboxDerHeader -Bytes $bytes -Offset 0)
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes,

        [Parameter(Mandatory)]
        [PSCustomObject] $Parent
    )

    $offset = $Parent.ValueOffset
    $end = $Parent.ValueOffset + $Parent.Length
    if ($end -gt $Bytes.Length) {
        throw [System.FormatException]::new('DER element is longer than the data that contains it.')
    }

    while ($offset -lt $end) {
        $child = Read-CertToolboxDerHeader -Bytes $Bytes -Offset $offset
        if (-not $child -or $child.ValueOffset + $child.Length -gt $end) {
            throw [System.FormatException]::new("Malformed DER element at offset $offset.")
        }
        $child
        $offset = $child.ValueOffset + $child.Length
    }
}

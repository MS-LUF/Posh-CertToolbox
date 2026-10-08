function Read-CertToolboxImapResponse {
    <#
    .SYNOPSIS
        Reads the IMAP server's response to one tagged command.
    .DESCRIPTION
        The response to an IMAP command (RFC 3501, section 2.2.2) is any number of untagged
        lines (starting with "*") followed by one line starting with the command's own tag and
        a status of OK, NO or BAD.
    .PARAMETER Stream
        The connected stream to read from.
    .PARAMETER Tag
        The tag of the command whose completion to wait for.
    .OUTPUTS
        PSCustomObject with Status (OK, NO or BAD, upper case) and Line (every line received,
        the tagged one last).
    .EXAMPLE
        Read-CertToolboxImapResponse -Stream $stream -Tag 'ct1'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [System.IO.Stream] $Stream,

        [Parameter(Mandatory)]
        [string] $Tag
    )

    $lines = [System.Collections.Generic.List[string]]::new()
    $status = $null
    while ($null -eq $status) {
        $line = Read-CertToolboxTextLine -Stream $Stream
        $lines.Add($line)
        if ($line -match ('^' + [regex]::Escape($Tag) + '\s+(?<status>\S+)')) {
            $status = $Matches['status'].ToUpperInvariant()
        } elseif ($lines.Count -ge $script:CertToolboxStartTlsMaxReplyLine) {
            throw [System.Net.ProtocolViolationException]::new("The IMAP server sent more than $($script:CertToolboxStartTlsMaxReplyLine) lines without completing the command.")
        }
    }

    [PSCustomObject]@{
        Status = $status
        Line   = $lines.ToArray()
    }
}

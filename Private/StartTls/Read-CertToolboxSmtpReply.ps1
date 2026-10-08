function Read-CertToolboxSmtpReply {
    <#
    .SYNOPSIS
        Reads one complete SMTP reply, which may span several lines.
    .DESCRIPTION
        An SMTP reply (RFC 5321, section 4.2) is one or more lines starting with the same
        three-digit code; every line but the last has a hyphen after the code, the last has a
        space (or nothing).
    .PARAMETER Stream
        The connected stream to read from.
    .OUTPUTS
        PSCustomObject with Code (int) and Line (every line of the reply, as received).
    .EXAMPLE
        Read-CertToolboxSmtpReply -Stream $stream
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [System.IO.Stream] $Stream
    )

    $lines = [System.Collections.Generic.List[string]]::new()
    while ($true) {
        $line = Read-CertToolboxTextLine -Stream $Stream
        if ($line -notmatch '^\d{3}([ -]|$)') {
            throw [System.Net.ProtocolViolationException]::new("Unexpected reply from the SMTP server: $line")
        }
        $lines.Add($line)
        if ($line -notmatch '^\d{3}-') {
            break
        }
        if ($lines.Count -ge $script:CertToolboxStartTlsMaxReplyLine) {
            throw [System.Net.ProtocolViolationException]::new("The SMTP server sent a reply of more than $($script:CertToolboxStartTlsMaxReplyLine) lines.")
        }
    }

    [PSCustomObject]@{
        Code = [int]$lines[$lines.Count - 1].Substring(0, 3)
        Line = $lines.ToArray()
    }
}

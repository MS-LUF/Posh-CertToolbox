function Invoke-CertToolboxSmtpStartTls {
    <#
    .SYNOPSIS
        Performs the plaintext SMTP exchange that precedes a TLS handshake (RFC 3207).
    .DESCRIPTION
        Reads the server greeting (220), sends EHLO, checks that the server advertises the
        STARTTLS extension, sends STARTTLS and expects 220. When this returns, the next bytes
        on the stream are the TLS handshake.

        Throws when the server greets with anything but 220, rejects EHLO, does not advertise
        STARTTLS, or refuses the command; the message quotes the server's own reply.
    .PARAMETER Stream
        The connected stream to the SMTP server.
    .PARAMETER EhloName
        The name to announce in EHLO. Defaults to this machine's host name. Some servers reject
        or delay a client that announces an implausible name.
    .OUTPUTS
        System.String. The dialogue, one line per string, prefixed "C: " (client) or "S: "
        (server).
    .EXAMPLE
        Invoke-CertToolboxSmtpStartTls -Stream $client.GetStream()
    #>
    [CmdletBinding()]
    [OutputType([string])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'StartTls is the name of the mechanism, not a plural - PSUseSingularNouns false-positives on the trailing "s" of TLS.')]
    param(
        [Parameter(Mandatory)]
        [System.IO.Stream] $Stream,

        [Parameter()]
        [string] $EhloName
    )

    if (-not $EhloName) {
        $EhloName = [System.Net.Dns]::GetHostName()
    }

    $greeting = Read-CertToolboxSmtpReply -Stream $Stream
    $greeting.Line | ForEach-Object { "S: $_" }
    if ($greeting.Code -ne 220) {
        throw [System.Net.ProtocolViolationException]::new("The SMTP server did not greet with 220: $($greeting.Line -join ' / ')")
    }

    "C: EHLO $EhloName"
    Send-CertToolboxTextLine -Stream $Stream -Line "EHLO $EhloName"
    $ehlo = Read-CertToolboxSmtpReply -Stream $Stream
    $ehlo.Line | ForEach-Object { "S: $_" }
    if ($ehlo.Code -ne 250) {
        throw [System.Net.ProtocolViolationException]::new("The SMTP server rejected EHLO: $($ehlo.Line -join ' / ')")
    }

    # Each line after the code and its separator is one extension keyword, optionally followed
    # by parameters (RFC 5321, section 4.1.1.1).
    $advertised = @($ehlo.Line | Where-Object { $_ -match '^\d{3}[ -]STARTTLS(\s|$)' }).Count -gt 0
    if (-not $advertised) {
        throw [System.Net.ProtocolViolationException]::new('The SMTP server does not advertise STARTTLS in its EHLO reply.')
    }

    'C: STARTTLS'
    Send-CertToolboxTextLine -Stream $Stream -Line 'STARTTLS'
    $reply = Read-CertToolboxSmtpReply -Stream $Stream
    $reply.Line | ForEach-Object { "S: $_" }
    if ($reply.Code -ne 220) {
        throw [System.Net.ProtocolViolationException]::new("The SMTP server refused STARTTLS: $($reply.Line -join ' / ')")
    }
}

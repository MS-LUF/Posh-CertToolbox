function Invoke-CertToolboxImapStartTls {
    <#
    .SYNOPSIS
        Performs the plaintext IMAP exchange that precedes a TLS handshake (RFC 3501, section
        6.2.1).
    .DESCRIPTION
        Reads the server greeting, sends CAPABILITY, checks that the server lists STARTTLS,
        sends STARTTLS and expects a tagged OK. When this returns, the next bytes on the stream
        are the TLS handshake.

        The capabilities are always queried, even when the greeting already lists them, so the
        check does not depend on an optional part of the greeting.

        Throws when the greeting is not "* OK" (a server that greets with PREAUTH has already
        authenticated the connection and does not accept STARTTLS), when STARTTLS is not
        listed, or when the command is refused; the message quotes the server's own reply.
    .PARAMETER Stream
        The connected stream to the IMAP server.
    .OUTPUTS
        System.String. The dialogue, one line per string, prefixed "C: " (client) or "S: "
        (server).
    .EXAMPLE
        Invoke-CertToolboxImapStartTls -Stream $client.GetStream()
    #>
    [CmdletBinding()]
    [OutputType([string])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'StartTls is the name of the mechanism, not a plural - PSUseSingularNouns false-positives on the trailing "s" of TLS.')]
    param(
        [Parameter(Mandatory)]
        [System.IO.Stream] $Stream
    )

    $greeting = Read-CertToolboxTextLine -Stream $Stream
    "S: $greeting"
    if ($greeting -notmatch '^\*\s+OK(\s|$)') {
        throw [System.Net.ProtocolViolationException]::new("The IMAP server did not greet with '* OK': $greeting")
    }

    'C: ct1 CAPABILITY'
    Send-CertToolboxTextLine -Stream $Stream -Line 'ct1 CAPABILITY'
    $capability = Read-CertToolboxImapResponse -Stream $Stream -Tag 'ct1'
    $capability.Line | ForEach-Object { "S: $_" }
    if ($capability.Status -ne 'OK') {
        throw [System.Net.ProtocolViolationException]::new("The IMAP server rejected CAPABILITY: $($capability.Line[-1])")
    }

    $advertised = $false
    foreach ($line in $capability.Line) {
        if ($line -match '^\*\s+CAPABILITY\s+(?<list>.*)$') {
            if (($Matches['list'] -split '\s+') -contains 'STARTTLS') {
                $advertised = $true
            }
        }
    }
    if (-not $advertised) {
        throw [System.Net.ProtocolViolationException]::new('The IMAP server does not list STARTTLS in its capabilities.')
    }

    'C: ct2 STARTTLS'
    Send-CertToolboxTextLine -Stream $Stream -Line 'ct2 STARTTLS'
    $reply = Read-CertToolboxImapResponse -Stream $Stream -Tag 'ct2'
    $reply.Line | ForEach-Object { "S: $_" }
    if ($reply.Status -ne 'OK') {
        throw [System.Net.ProtocolViolationException]::new("The IMAP server refused STARTTLS: $($reply.Line[-1])")
    }
}

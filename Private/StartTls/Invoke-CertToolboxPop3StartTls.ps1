function Invoke-CertToolboxPop3StartTls {
    <#
    .SYNOPSIS
        Performs the plaintext POP3 exchange that precedes a TLS handshake (RFC 2595, section 4).
    .DESCRIPTION
        Reads the server greeting (+OK), sends CAPA, checks that the server lists STLS, sends
        STLS and expects +OK. When this returns, the next bytes on the stream are the TLS
        handshake.

        CAPA itself is an optional command (RFC 2449). A server that answers it with an error
        cannot tell whether it supports STLS, so in that one case STLS is attempted anyway and
        the server's answer to it decides.

        Throws when the greeting is not +OK, when the capability list does not contain STLS, or
        when STLS is refused; the message quotes the server's own reply.
    .PARAMETER Stream
        The connected stream to the POP3 server.
    .OUTPUTS
        System.String. The dialogue, one line per string, prefixed "C: " (client) or "S: "
        (server).
    .EXAMPLE
        Invoke-CertToolboxPop3StartTls -Stream $client.GetStream()
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
    if ($greeting -notmatch '^\+OK(\s|$)') {
        throw [System.Net.ProtocolViolationException]::new("The POP3 server did not greet with +OK: $greeting")
    }

    'C: CAPA'
    Send-CertToolboxTextLine -Stream $Stream -Line 'CAPA'
    $capaStatus = Read-CertToolboxTextLine -Stream $Stream
    "S: $capaStatus"

    if ($capaStatus -match '^\+OK(\s|$)') {
        # A multi-line response ends with a line holding a single dot.
        $advertised = $false
        $count = 0
        while ($true) {
            $line = Read-CertToolboxTextLine -Stream $Stream
            "S: $line"
            if ($line -eq '.') {
                break
            }
            if ($line.Trim() -eq 'STLS') {
                $advertised = $true
            }
            $count++
            if ($count -ge $script:CertToolboxStartTlsMaxReplyLine) {
                throw [System.Net.ProtocolViolationException]::new("The POP3 server sent a capability list of more than $($script:CertToolboxStartTlsMaxReplyLine) lines.")
            }
        }
        if (-not $advertised) {
            throw [System.Net.ProtocolViolationException]::new('The POP3 server does not list STLS in its capabilities.')
        }
    } else {
        Write-Verbose 'The POP3 server does not support CAPA; trying STLS anyway.'
    }

    'C: STLS'
    Send-CertToolboxTextLine -Stream $Stream -Line 'STLS'
    $reply = Read-CertToolboxTextLine -Stream $Stream
    "S: $reply"
    if ($reply -notmatch '^\+OK(\s|$)') {
        throw [System.Net.ProtocolViolationException]::new("The POP3 server refused STLS: $reply")
    }
}

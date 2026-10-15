function Get-CertToolboxWireChain {
    <#
    .SYNOPSIS
        Reads the certificates a server sends, exactly as they are on the wire, from one
        hand-built handshake opening.
    .DESCRIPTION
        Sends a ClientHello offering TLS 1.2 and every earlier cipher suite of the registry,
        and reads the server's answer up to its Certificate message. That message is in clear
        text up to TLS 1.2, so the certificates are the server's own list, in its order, with
        nothing added or removed by any TLS stack. The handshake is never completed.

        Used where the operating system's TLS stack does not report what the server sent: on
        macOS the certificates handed to the validation callback are the chain the system
        completed, with intermediates it fetched and the root it added.

        A server that only accepts TLS 1.3 encrypts its Certificate message, so its chain
        cannot be read this way; Certificate is then empty and Reason says why.
    .PARAMETER Connection
        The connection settings, as a hashtable of Invoke-CertToolboxRawHello parameters
        (HostName, Port, and optionally TargetHost, TimeoutMs, StartTls, SmtpEhloName, Address,
        AddressFamily).
    .OUTPUTS
        PSCustomObject with Certificate (the certificates sent, leaf first, empty when they
        could not be read), Version (the TLS version code the server answered with) and Reason
        (why the certificates could not be read, or $null).
    .EXAMPLE
        Get-CertToolboxWireChain -Connection @{ HostName = 'www.example.com'; Port = 443 }
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Connection
    )

    $answer = Invoke-CertToolboxRawHello @Connection -Protocol Tls12 `
        -CipherSuite $script:CertToolboxLegacyCipherSuite -Group $script:CertToolboxLegacyProbeGroup

    $reason = $null
    if ($answer.Error) {
        $reason = "The handshake opening failed: $($answer.Error)"
    } elseif (-not $answer.ServerHello) {
        if ($answer.Alert) {
            $reason = "The server refused TLS 1.2 and earlier with the alert '$($answer.Alert)'; it may only accept TLS 1.3, which encrypts its certificates."
        } else {
            $reason = 'The server did not answer with a ServerHello.'
        }
    } elseif (@($answer.Certificate).Count -eq 0) {
        $reason = 'The server answered, but its certificates could not be read from the answer.'
    }

    $certificate = @()
    if (-not $reason) {
        $certificate = @($answer.Certificate)
    }

    [PSCustomObject]@{
        Certificate = $certificate
        Version     = $answer.Version
        Reason      = $reason
    }
}

function Invoke-CertToolboxTlsProbe {
    <#
    .SYNOPSIS
        Connects to an endpoint, performs one TLS handshake and returns the captured result.
    .DESCRIPTION
        The single network entry point shared by Get-CertToolboxTlsCertificate and
        Test-CertToolboxTlsProtocol: TCP connect (Connect-CertToolboxTcpClient), the optional
        plaintext upgrade exchange (Invoke-CertToolboxStartTls), handshake
        (Invoke-CertToolboxTlsHandshake), and guaranteed cleanup. Public cmdlet tests mock this
        one function.

        Throws the innermost exception on any connection, upgrade or handshake failure.
    .PARAMETER HostName
        DNS name or IP address to connect to.
    .PARAMETER Port
        TCP port to connect to.
    .PARAMETER TargetHost
        Name sent as SNI and matched against the certificate. Defaults to HostName.
    .PARAMETER SslProtocol
        Protocol versions to offer. None (the default) lets the operating system choose.
    .PARAMETER TimeoutMs
        Timeout, in milliseconds, for the TCP connect and for each socket read or write of the
        plaintext exchange and of the handshake.
    .PARAMETER CheckRevocation
        Asks the runtime to check certificate revocation while building the local chain.
    .PARAMETER StartTls
        The application protocol to speak in plaintext before TLS (Smtp, Imap or Pop3). Omit
        for a server that expects TLS from the first byte.
    .PARAMETER SmtpEhloName
        The name to announce in the SMTP EHLO command, when StartTls is Smtp.
    .OUTPUTS
        The Invoke-CertToolboxTlsHandshake object, plus RemoteAddress, ElapsedMs and
        StartTlsDialogue (the plaintext exchange, empty for direct TLS).
    .EXAMPLE
        Invoke-CertToolboxTlsProbe -HostName 'example.com' -Port 443
    .EXAMPLE
        Invoke-CertToolboxTlsProbe -HostName 'mail.example.com' -Port 587 -StartTls Smtp
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string] $HostName,

        [Parameter(Mandatory)]
        [int] $Port,

        [Parameter()]
        [string] $TargetHost,

        [Parameter()]
        [System.Security.Authentication.SslProtocols] $SslProtocol = [System.Security.Authentication.SslProtocols]::None,

        [Parameter()]
        [int] $TimeoutMs = 10000,

        [Parameter()]
        [switch] $CheckRevocation,

        [Parameter()]
        [ValidateSet('Smtp', 'Imap', 'Pop3')]
        [string] $StartTls,

        [Parameter()]
        [string] $SmtpEhloName
    )

    if (-not $TargetHost) {
        $TargetHost = $HostName
    }

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $client = $null
    try {
        $client = Connect-CertToolboxTcpClient -HostName $HostName -Port $Port -TimeoutMs $TimeoutMs
        $remoteAddress = $client.Client.RemoteEndPoint.Address.ToString()
        $stream = $client.GetStream()

        $dialogue = @()
        if ($StartTls) {
            $dialogue = @(Invoke-CertToolboxStartTls -StartTls $StartTls -Stream $stream -SmtpEhloName $SmtpEhloName)
        }

        $result = Invoke-CertToolboxTlsHandshake -Stream $stream -TargetHost $TargetHost `
            -SslProtocol $SslProtocol -CheckRevocation:$CheckRevocation

        $stopwatch.Stop()
        $result | Add-Member -NotePropertyName RemoteAddress -NotePropertyValue $remoteAddress
        $result | Add-Member -NotePropertyName ElapsedMs -NotePropertyValue ([int]$stopwatch.ElapsedMilliseconds)
        $result | Add-Member -NotePropertyName StartTlsDialogue -NotePropertyValue $dialogue
        $result
    } catch {
        throw (Resolve-CertToolboxException -Exception $_.Exception)
    } finally {
        if ($client) {
            $client.Close()
        }
    }
}

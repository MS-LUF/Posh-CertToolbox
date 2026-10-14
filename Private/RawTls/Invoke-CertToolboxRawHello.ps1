function Invoke-CertToolboxRawHello {
    <#
    .SYNOPSIS
        Opens a connection, sends one hand-built ClientHello and returns the server's answer.
    .DESCRIPTION
        The single network entry point of the raw probe, so that everything built on it can be
        tested with a mock: TCP connect (Connect-CertToolboxTcpClient), the optional plaintext
        upgrade exchange (Invoke-CertToolboxStartTls), the ClientHello
        (ConvertTo-CertToolboxClientHello), the server's answer (Read-CertToolboxServerFlight),
        and guaranteed cleanup. The handshake is never completed.

        Never throws. A failure is reported in Error, with Stage telling where it happened:
        Connect (the server could not be reached or did not offer the upgrade) or Handshake (it
        was reached but did not answer the hello with TLS). The difference matters to the
        caller: the first means the endpoint is unusable, the second is an answer about what
        was offered.
    .PARAMETER HostName
        DNS name or IP address to connect to.
    .PARAMETER Port
        TCP port to connect to.
    .PARAMETER TargetHost
        Server name to send. Defaults to HostName.
    .PARAMETER Protocol
        The single protocol version to offer.
    .PARAMETER CipherSuite
        The cipher suites to offer, by their IANA number.
    .PARAMETER Group
        The key-exchange groups to offer, by their IANA number.
    .PARAMETER TimeoutMs
        Timeout, in milliseconds, for the TCP connect and for each socket read or write.
    .PARAMETER StartTls
        The application protocol to speak in plaintext first (Smtp, Imap or Pop3).
    .PARAMETER SmtpEhloName
        The name to announce in the SMTP EHLO command, when StartTls is Smtp.
    .PARAMETER Address
        Connect to this address and no other, instead of resolving HostName.
    .PARAMETER AddressFamily
        When resolving HostName, use only its IPv4 or only its IPv6 addresses.
    .OUTPUTS
        The Read-CertToolboxServerFlight object, plus RemoteAddress, Error and Stage.
    .EXAMPLE
        Invoke-CertToolboxRawHello -HostName 'www.example.com' -Port 443 -Protocol Tls12 -CipherSuite 0xC02F -Group 29, 23
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

        [Parameter(Mandatory)]
        [ValidateSet('Ssl3', 'Tls', 'Tls11', 'Tls12', 'Tls13')]
        [string] $Protocol,

        [Parameter(Mandatory)]
        [int[]] $CipherSuite,

        [Parameter()]
        [AllowEmptyCollection()]
        [int[]] $Group = @(),

        [Parameter()]
        [int] $TimeoutMs = 10000,

        [Parameter()]
        [ValidateSet('Smtp', 'Imap', 'Pop3')]
        [string] $StartTls,

        [Parameter()]
        [string] $SmtpEhloName,

        [Parameter()]
        [System.Net.IPAddress] $Address,

        [Parameter()]
        [ValidateSet('IPv4', 'IPv6')]
        [string] $AddressFamily
    )

    if (-not $TargetHost) {
        $TargetHost = $HostName
    }

    $connectParameter = @{ HostName = $HostName; Port = $Port; TimeoutMs = $TimeoutMs }
    if ($Address) {
        $connectParameter.Address = $Address
    }
    if ($AddressFamily) {
        $connectParameter.AddressFamily = $AddressFamily
    }

    $result = $null
    $remoteAddress = $null
    $failure = $null
    $stage = 'Connect'
    $client = $null
    try {
        $client = Connect-CertToolboxTcpClient @connectParameter
        $remoteAddress = $client.Client.RemoteEndPoint.Address.ToString()
        $stream = $client.GetStream()

        if ($StartTls) {
            $null = Invoke-CertToolboxStartTls -StartTls $StartTls -Stream $stream -SmtpEhloName $SmtpEhloName
        }

        $stage = 'Handshake'
        $hello = ConvertTo-CertToolboxClientHello -Protocol $Protocol -CipherSuite $CipherSuite -ServerName $TargetHost -Group $Group
        $stream.Write($hello, 0, $hello.Length)
        $stream.Flush()

        $result = Read-CertToolboxServerFlight -Stream $stream
    } catch {
        $failure = (Resolve-CertToolboxException -Exception $_.Exception).Message
    } finally {
        if ($client) {
            $client.Close()
        }
    }

    if (-not $result) {
        $result = [PSCustomObject]@{
            ServerHello          = $false
            Version              = $null
            CipherSuite          = $null
            Group                = $null
            HelloRetryRequest    = $false
            ExtendedMasterSecret = $false
            SecureRenegotiation  = $false
            Alert                = $null
            Certificate          = @()
            OcspStapled          = $false
            Complete             = $false
        }
    }

    $result | Add-Member -NotePropertyName RemoteAddress -NotePropertyValue $remoteAddress
    $result | Add-Member -NotePropertyName Error -NotePropertyValue $failure
    $result | Add-Member -NotePropertyName Stage -NotePropertyValue $(if ($failure) { $stage } else { $null })
    $result
}

function Test-CertToolboxTlsProtocol {
    <#
    .SYNOPSIS
        Probes a TLS endpoint once per protocol version and reports which ones could be
        negotiated.
    .DESCRIPTION
        Makes a separate connection for each protocol version, offering only that version, and
        returns one result per version.

        Read the Negotiated property as "could be negotiated from this machine", not as "the
        server supports it". The handshake is done by the operating system's TLS stack, and a
        version that the local system has disabled or does not implement fails here whatever the
        server accepts; ErrorType and ErrorMessage carry the underlying failure so the two cases
        can be told apart. A $true result is always conclusive; a $false one only is when the
        same version works from this machine against another server.

        Mail servers that start in plaintext and upgrade to TLS are probed with the StartTls
        parameter; the plaintext exchange is then repeated on each connection. When that
        exchange itself fails (the server does not offer the upgrade, for instance), every
        version is reported as not negotiated with that error.

        The default display is a table of the main columns; pipe the result to Format-List
        with an asterisk to see every property, the negotiated cipher suite among them.
    .PARAMETER HostName
        One or more DNS names or IP addresses to connect to.
    .PARAMETER Port
        TCP port. Defaults to 443, or with StartTls to the protocol's standard port: 25 for
        Smtp, 143 for Imap, 110 for Pop3.
    .PARAMETER TargetHost
        Name sent as SNI, when it differs from HostName.
    .PARAMETER Protocol
        The protocol versions to probe. Defaults to all of Ssl3, Tls, Tls11, Tls12 and Tls13.
    .PARAMETER TimeoutSec
        Timeout, in seconds, for each connection and each step of its handshake.
    .PARAMETER StartTls
        The mail protocol to speak in plaintext before upgrading to TLS: Smtp, Imap or Pop3.
        Omit it for a server that expects TLS from the first byte.
    .PARAMETER SmtpEhloName
        The name announced in the SMTP EHLO command, with StartTls Smtp. Defaults to this
        machine's host name.
    .PARAMETER EveryAddress
        Probes every IP address the name resolves to, instead of the first one that answers,
        and returns one set of results per address; RemoteAddress tells them apart. An address
        that cannot be reached shows as not negotiated for every version, with the error.
    .PARAMETER AddressFamily
        Uses only the IPv4 or only the IPv6 addresses of the name.
    .INPUTS
        System.String. Host names as strings, or objects with HostName, Port, TargetHost and StartTls properties.
    .OUTPUTS
        PSCustomObject (type name CertToolbox.TlsProtocolResult), one per host and protocol.
    .EXAMPLE
        Test-CertToolboxTlsProtocol -HostName 'www.example.com' | Format-Table Protocol, Negotiated, CipherSuite, ErrorMessage
    .EXAMPLE
        Test-CertToolboxTlsProtocol -HostName 'mail.example.com' -Port 993 -Protocol Tls12, Tls13
    .EXAMPLE
        Test-CertToolboxTlsProtocol -HostName 'mail.example.com' -StartTls Smtp

        Probes the TLS versions of a mail server on port 25, upgrading with STARTTLS each time.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('ComputerName', 'DnsName')]
        [ValidateNotNullOrEmpty()]
        [string[]] $HostName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1, 65535)]
        [int] $Port = 443,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('ServerName', 'SNI')]
        [string] $TargetHost,

        [Parameter()]
        [ValidateSet('Ssl3', 'Tls', 'Tls11', 'Tls12', 'Tls13')]
        [string[]] $Protocol = @('Ssl3', 'Tls', 'Tls11', 'Tls12', 'Tls13'),

        [Parameter()]
        [ValidateRange(1, 600)]
        [int] $TimeoutSec = 10,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Smtp', 'Imap', 'Pop3')]
        [string] $StartTls,

        [Parameter()]
        [ValidatePattern('^[A-Za-z0-9.:\[\]-]+$')]
        [string] $SmtpEhloName,

        [Parameter()]
        [switch] $EveryAddress,

        [Parameter()]
        [ValidateSet('IPv4', 'IPv6')]
        [string] $AddressFamily
    )

    begin {
        $config = Read-CertToolboxConfigFile
        Write-CertToolboxLog -Config $config -Level Debug -CmdletName $MyInvocation.MyCommand.Name `
            -Message 'Cmdlet invoked' -BoundParameters $PSBoundParameters
    }

    process {
        $targetParameter = @{ HostName = $HostName; EveryAddress = $EveryAddress }
        if ($AddressFamily) {
            $targetParameter.AddressFamily = $AddressFamily
        }

        foreach ($entry in (Get-CertToolboxProbeTarget @targetParameter)) {
            $item = $entry.HostName
            $serverName = $TargetHost
            if (-not $serverName) {
                $serverName = $item
            }

            # A separate variable, not $Port itself: with pipeline input the parameter is bound
            # again for each object, and a value assigned to it here must not leak into the next.
            $endpointPort = $Port
            if ($StartTls -and -not $PSBoundParameters.ContainsKey('Port')) {
                $endpointPort = $script:CertToolboxStartTlsDefaultPort[$StartTls]
            }

            $startTlsValue = $null
            $probeParameter = @{
                HostName   = $item
                Port       = $endpointPort
                TargetHost = $serverName
                TimeoutMs  = $TimeoutSec * 1000
            }
            if ($StartTls) {
                $startTlsValue = $StartTls
                $probeParameter.StartTls = $StartTls
                if ($SmtpEhloName) {
                    $probeParameter.SmtpEhloName = $SmtpEhloName
                }
            }

            $target = "$($entry.Label):$endpointPort"
            if ($entry.Error) {
                Write-CertToolboxLog -Config $config -Level Error -CmdletName $MyInvocation.MyCommand.Name `
                    -Target $target -Message "The name could not be resolved: $($entry.Error.Message)"
                $PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]::new(
                        $entry.Error, 'TlsConnectionFailed', [System.Management.Automation.ErrorCategory]::ConnectionError, $target))
                continue
            }
            if ($entry.Address) {
                $probeParameter.Address = $entry.Address
            }
            if ($AddressFamily) {
                $probeParameter.AddressFamily = $AddressFamily
            }

            foreach ($protocolName in $Protocol) {
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                $probe = $null
                $errorType = $null
                $errorMessage = $null

                try {
                    Write-Verbose "Probing $target with $protocolName only (StartTls '$StartTls')."
                    $probe = Invoke-CertToolboxTlsProbe @probeParameter -SslProtocol ([System.Security.Authentication.SslProtocols]$protocolName)
                } catch {
                    $exception = Resolve-CertToolboxException -Exception $_.Exception
                    $errorType = $exception.GetType().Name
                    $errorMessage = $exception.Message
                }
                $stopwatch.Stop()

                # Known from the connection when it succeeded, from the target when a specific
                # address was probed, and unknown otherwise.
                $remoteAddress = $null
                if ($probe) {
                    $remoteAddress = $probe.RemoteAddress
                } elseif ($entry.Address) {
                    $remoteAddress = "$($entry.Address)"
                }

                if ($probe -and @($probe.StartTlsDialogue).Count -gt 0) {
                    Write-CertToolboxLog -Config $config -Level Debug -CmdletName $MyInvocation.MyCommand.Name `
                        -Target $target -Message "$StartTls dialogue before TLS: $(@($probe.StartTlsDialogue) -join ' | ')"
                }

                $result = [ordered]@{
                    PSTypeName           = 'CertToolbox.TlsProtocolResult'
                    HostName             = $item
                    Port                 = $endpointPort
                    TargetHost           = $serverName
                    RemoteAddress        = $remoteAddress
                    StartTls             = $startTlsValue
                    Protocol             = $protocolName
                    Negotiated           = ($null -ne $probe)
                    NegotiatedProtocol   = $null
                    CipherSuite          = $null
                    CipherAlgorithm      = $null
                    CipherStrength       = $null
                    KeyExchangeAlgorithm = $null
                    ErrorType            = $errorType
                    ErrorMessage         = $errorMessage
                    ElapsedMs            = [int]$stopwatch.ElapsedMilliseconds
                }
                if ($probe) {
                    $result.NegotiatedProtocol = $probe.Protocol
                    $result.CipherSuite = $probe.CipherSuite
                    $result.CipherAlgorithm = $probe.CipherAlgorithm
                    $result.CipherStrength = $probe.CipherStrength
                    $result.KeyExchangeAlgorithm = $probe.KeyExchangeAlgorithm
                }

                # A version that cannot be negotiated is a result of the probe, not a failure of
                # the cmdlet, so it is logged at Information level like a successful one.
                $summary = "${protocolName}: not negotiated ($errorType`: $errorMessage)"
                if ($probe) {
                    $summary = "${protocolName}: negotiated ($($probe.Protocol))"
                }
                Write-CertToolboxLog -Config $config -Level Information -CmdletName $MyInvocation.MyCommand.Name `
                    -Target $target -Message $summary

                [PSCustomObject]$result
            }
        }
    }
}

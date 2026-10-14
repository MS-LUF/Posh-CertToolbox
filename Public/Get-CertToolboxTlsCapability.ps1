function Get-CertToolboxTlsCapability {
    <#
    .SYNOPSIS
        Finds what a TLS server supports: protocol versions, cipher suites, key-exchange groups
        and a few handshake features.
    .DESCRIPTION
        Sends hand-built handshake openings and reads how the server answers, without ever
        completing a handshake. What is offered therefore does not depend on what this
        machine's own TLS stack has enabled, and the result is a statement about the server.
        This is the difference with Test-CertToolboxTlsProtocol, which tells what this machine
        can negotiate; comparing the two shows whether a failure is the server's or the
        client's.

        Protocol lists each version probed, whether the server accepts it, how many cipher
        suites it accepts for it, and otherwise why not (the alert it sent, or what it
        answered instead).

        CipherSuite lists every suite accepted, per version, in the order the server picks
        them, from the whole IANA registry. ForwardSecrecy, AuthenticatedEncryption and Weak
        are facts read from the suite's name; Weak marks suites with no encryption, no server
        authentication, an export-grade key, or RC4, RC2, DES, 3DES, IDEA or MD5.
        ServerCipherOrder, in Protocol, tells whether that order is imposed by the server or
        merely follows the order of the offer.

        Group lists the key-exchange groups accepted, for TLS 1.3 and for the highest earlier
        version the server accepts.

        OcspStapling, SecureRenegotiation, ExtendedMasterSecret and WireChain (the certificate
        chain exactly as sent, duplicates and order included) are read from a handshake of TLS
        1.2 or earlier. They are empty for a server that only accepts TLS 1.3, where everything
        after the first server message is encrypted.

        A full scan makes one connection per accepted cipher suite and per group tried,
        typically 20 to 60 per host, and the server will see each as an abandoned handshake.
        Use the Protocol parameter to narrow it. SSL 2.0 is not probed.

        The default display is a summary: the accepted versions, the number of cipher suites
        and how many are weak, the group names. The Protocol, CipherSuite, Group and WireChain
        properties hold the full lists, each shown as a table; pipe the result to Format-List
        with an asterisk to see every property.
    .PARAMETER HostName
        One or more DNS names or IP addresses to connect to.
    .PARAMETER Port
        TCP port. Defaults to 443, or with StartTls to the protocol's standard port: 25 for
        Smtp, 143 for Imap, 110 for Pop3.
    .PARAMETER TargetHost
        Server name to send, when it differs from HostName.
    .PARAMETER Protocol
        The protocol versions to probe. Defaults to all of Ssl3, Tls, Tls11, Tls12 and Tls13.
    .PARAMETER TimeoutSec
        Timeout, in seconds, for each connection and each read.
    .PARAMETER StartTls
        The mail protocol to speak in plaintext before TLS: Smtp, Imap or Pop3. The exchange is
        repeated on every connection.
    .PARAMETER SmtpEhloName
        The name announced in the SMTP EHLO command, with StartTls Smtp. Defaults to this
        machine's host name.
    .PARAMETER EveryAddress
        Scans every IP address the name resolves to, instead of the first one that answers,
        and returns one result per address; RemoteAddress tells them apart. The whole scan is
        repeated for each address, so the number of connections is multiplied accordingly:
        combine it with the Protocol parameter.
    .PARAMETER AddressFamily
        Uses only the IPv4 or only the IPv6 addresses of the name.
    .INPUTS
        System.String. Host names as strings, or objects with HostName, Port, TargetHost and StartTls properties.
    .OUTPUTS
        PSCustomObject (type name CertToolbox.TlsCapability), one per host.
    .EXAMPLE
        (Get-CertToolboxTlsCapability -HostName 'www.example.com').Protocol | Format-Table

        Scans a server and shows which protocol versions it accepts.
    .EXAMPLE
        (Get-CertToolboxTlsCapability -HostName 'www.example.com').CipherSuite | Format-Table Protocol, Order, Name, ForwardSecrecy, Weak

        Shows the cipher suites the server accepts, per version, in the order it picks them.
    .EXAMPLE
        (Get-CertToolboxTlsCapability 'www.example.com').CipherSuite | Where-Object Weak

        Lists the weak cipher suites a server still accepts.
    .EXAMPLE
        Get-CertToolboxTlsCapability -HostName 'mail.example.com' -StartTls Smtp -Protocol Tls12, Tls13

        Scans a mail server on port 25 for TLS 1.2 and 1.3 only.
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

        # Oldest first, whatever order they were given in, and each once.
        $versions = @('Ssl3', 'Tls', 'Tls11', 'Tls12', 'Tls13' | Where-Object { $Protocol -contains $_ })
    }

    process {
        $targetParameter = @{ HostName = $HostName; EveryAddress = $EveryAddress }
        if ($AddressFamily) {
            $targetParameter.AddressFamily = $AddressFamily
        }

        foreach ($entry in (Get-CertToolboxProbeTarget @targetParameter)) {
            $item = $entry.HostName
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

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
            $connection = @{
                HostName   = $item
                Port       = $endpointPort
                TargetHost = $serverName
                TimeoutMs  = $TimeoutSec * 1000
            }
            if ($StartTls) {
                $startTlsValue = $StartTls
                $connection.StartTls = $StartTls
                if ($SmtpEhloName) {
                    $connection.SmtpEhloName = $SmtpEhloName
                }
            }

            $target = "$($entry.Label):$endpointPort"
            if ($entry.Error) {
                Write-CertToolboxLog -Config $config -Level Error -CmdletName $MyInvocation.MyCommand.Name `
                    -Target $target -Message "The name could not be resolved: $($entry.Error.Message)"
                $PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]::new(
                        $entry.Error, 'TlsProbeFailed', [System.Management.Automation.ErrorCategory]::ConnectionError, $target))
                continue
            }
            if ($entry.Address) {
                $connection.Address = $entry.Address
            }
            if ($AddressFamily) {
                $connection.AddressFamily = $AddressFamily
            }

            try {
                $connectionCount = 0
                $scan = [System.Collections.Generic.List[object]]::new()
                foreach ($version in $versions) {
                    Write-Verbose "Probing $target for $version cipher suites."
                    $found = Find-CertToolboxServerCipherSuite -Connection $connection -Protocol $version
                    $connectionCount += $found.ConnectionCount

                    # If the very first probe cannot even connect, the endpoint is unusable and
                    # there is nothing to report about it.
                    if ($scan.Count -eq 0 -and $found.ConnectFailed) {
                        throw [System.InvalidOperationException]::new($found.Reason)
                    }
                    $scan.Add($found)
                }

                $protocolRow = @(foreach ($found in $scan) {
                        [PSCustomObject]@{
                            PSTypeName        = 'CertToolbox.TlsCapabilityProtocol'
                            Protocol          = $found.Protocol
                            Accepted          = $found.Accepted
                            CipherSuiteCount  = @($found.CipherSuite).Count
                            ServerCipherOrder = $found.ServerCipherOrder
                            Reason            = $found.Reason
                        }
                    })

                $suiteRow = @(foreach ($found in $scan) {
                        $order = 0
                        foreach ($code in $found.CipherSuite) {
                            $order++
                            $info = Get-CertToolboxCipherSuiteInfo -Code $code
                            [PSCustomObject]@{
                                PSTypeName              = 'CertToolbox.TlsCapabilityCipherSuite'
                                Protocol                = $found.Protocol
                                Order                   = $order
                                Name                    = $info.Name
                                Code                    = $info.Code
                                ForwardSecrecy          = $info.ForwardSecrecy
                                AuthenticatedEncryption = $info.AuthenticatedEncryption
                                Weak                    = $info.Weak
                            }
                        }
                    })

                # The highest version before TLS 1.3 that the server accepts: its handshake is
                # readable to the end, so it is the source of the chain and of the feature flags.
                $legacy = $scan | Where-Object { $_.Accepted -and $_.Protocol -ne 'Tls13' } | Select-Object -Last 1
                $modern = $scan | Where-Object { $_.Accepted -and $_.Protocol -eq 'Tls13' } | Select-Object -First 1

                $groupRow = @(foreach ($found in @($legacy, $modern)) {
                        if (-not $found) {
                            continue
                        }
                        Write-Verbose "Probing $target for $($found.Protocol) key-exchange groups."
                        $groups = Find-CertToolboxServerGroup -Connection $connection -Protocol $found.Protocol -CipherSuite $found.CipherSuite
                        $connectionCount += $groups.ConnectionCount
                        foreach ($code in $groups.Group) {
                            $name = $script:CertToolboxTlsGroupName[$code]
                            if (-not $name) {
                                $name = "group_$code"
                            }
                            [PSCustomObject]@{
                                PSTypeName = 'CertToolbox.TlsCapabilityGroup'
                                Protocol   = $found.Protocol
                                Name       = $name
                                Code       = $code
                            }
                        }
                    })

                $ocspStapling = $null
                $secureRenegotiation = $null
                $extendedMasterSecret = $null
                $wireChain = @()
                if ($legacy) {
                    $answer = $legacy.FirstAnswer
                    $secureRenegotiation = [bool]$answer.SecureRenegotiation
                    $extendedMasterSecret = [bool]$answer.ExtendedMasterSecret
                    # Stapling and the chain come after the ServerHello; they are only known when
                    # the rest of the server's answer could be read.
                    if ($answer.Complete) {
                        $ocspStapling = [bool]$answer.OcspStapled
                    }
                    $wireChain = @($answer.Certificate | ForEach-Object { ConvertTo-CertToolboxCertificateInfo -Certificate $_ })
                }

                $remoteAddress = ($scan | ForEach-Object { $_.FirstAnswer } | Where-Object { $_ } | Select-Object -First 1).RemoteAddress
                if (-not $remoteAddress -and $entry.Address) {
                    $remoteAddress = "$($entry.Address)"
                }
                $stopwatch.Stop()

                $accepted = @($protocolRow | Where-Object Accepted | ForEach-Object { $_.Protocol })
                $weak = @($suiteRow | Where-Object Weak)
                Write-CertToolboxLog -Config $config -Level Information -CmdletName $MyInvocation.MyCommand.Name `
                    -Target $target `
                    -Message "Accepted versions: $(if ($accepted.Count) { $accepted -join ', ' } else { 'none' }); $($suiteRow.Count) cipher suite(s), $($weak.Count) weak; $connectionCount connection(s)."

                [PSCustomObject]@{
                    PSTypeName           = 'CertToolbox.TlsCapability'
                    HostName             = $item
                    Port                 = $endpointPort
                    TargetHost           = $serverName
                    StartTls             = $startTlsValue
                    RemoteAddress        = $remoteAddress
                    Protocol             = $protocolRow
                    CipherSuite          = $suiteRow
                    Group                = $groupRow
                    OcspStapling         = $ocspStapling
                    SecureRenegotiation  = $secureRenegotiation
                    ExtendedMasterSecret = $extendedMasterSecret
                    WireChain            = $wireChain
                    ConnectionCount      = $connectionCount
                    ElapsedMs            = [int]$stopwatch.ElapsedMilliseconds
                }
            } catch {
                $exception = Resolve-CertToolboxException -Exception $_.Exception
                Write-CertToolboxLog -Config $config -Level Error -CmdletName $MyInvocation.MyCommand.Name `
                    -Target $target -Message "The endpoint could not be probed: $($exception.Message)"
                $PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]::new(
                        $exception, 'TlsProbeFailed', [System.Management.Automation.ErrorCategory]::ConnectionError, $target))
            }
        }
    }
}

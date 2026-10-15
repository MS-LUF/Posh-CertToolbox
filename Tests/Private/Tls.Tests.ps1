BeforeDiscovery {
    Import-Module (Join-Path $PSScriptRoot '../../Posh-CertToolbox.psd1') -Force
}

Describe 'Private/Tls' -Tag Unit {
    InModuleScope 'Posh-CertToolbox' {
        Describe 'Resolve-CertToolboxException' {
            It 'returns the innermost exception' {
                $inner = [System.InvalidOperationException]::new('root cause')
                $middle = [System.Exception]::new('middle', $inner)
                $outer = [System.Exception]::new('outer', $middle)

                (Resolve-CertToolboxException -Exception $outer).Message | Should -Be 'root cause'
            }

            It 'returns the exception itself when it has no inner exception' {
                $only = [System.TimeoutException]::new('alone')
                Resolve-CertToolboxException -Exception $only | Should -Be $only
            }
        }

        # These use a real loopback listener rather than mocks: the point is to confirm how the
        # real socket and SslStream behave on the runtime under test, fully offline.
        Describe 'Connect-CertToolboxTcpClient' {
            BeforeEach {
                $script:listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
                $script:listener.Start()
                $script:port = $script:listener.LocalEndpoint.Port
            }

            AfterEach {
                $script:listener.Stop()
            }

            It 'connects and applies the timeout to the socket' {
                $client = Connect-CertToolboxTcpClient -HostName '127.0.0.1' -Port $script:port -TimeoutMs 4000
                try {
                    $client.Connected | Should -BeTrue
                    $client.ReceiveTimeout | Should -Be 4000
                    $client.SendTimeout | Should -Be 4000
                } finally {
                    $client.Close()
                }
            }

            It 'throws the underlying socket error when nothing listens on the port' {
                $closedPort = $script:port
                $script:listener.Stop()

                { Connect-CertToolboxTcpClient -HostName '127.0.0.1' -Port $closedPort -TimeoutMs 4000 } |
                    Should -Throw -ExceptionType ([System.Net.Sockets.SocketException])
            }
        }

        Describe 'Connect-CertToolboxTcpClient to a chosen address' {
            BeforeEach {
                $script:listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
                $script:listener.Start()
                $script:port = $script:listener.LocalEndpoint.Port
            }

            AfterEach {
                $script:listener.Stop()
            }

            It 'connects to the address given without resolving the name' {
                Mock Resolve-CertToolboxHostAddress { throw 'the name must not be resolved' }

                $client = Connect-CertToolboxTcpClient -HostName 'name.that.does.not.exist.invalid' -Port $script:port -Address ([System.Net.IPAddress]::Loopback) -TimeoutMs 4000
                try {
                    $client.Connected | Should -BeTrue
                    $client.Client.RemoteEndPoint.Address.ToString() | Should -Be '127.0.0.1'
                } finally {
                    $client.Close()
                }
                Should -Invoke Resolve-CertToolboxHostAddress -Times 0 -Exactly
            }

            It 'resolves the name within the family asked for' {
                Mock Resolve-CertToolboxHostAddress { [System.Net.IPAddress]::Loopback }

                $client = Connect-CertToolboxTcpClient -HostName 'some.test.example' -Port $script:port -AddressFamily IPv4 -TimeoutMs 4000
                $client.Close()

                Should -Invoke Resolve-CertToolboxHostAddress -Times 1 -Exactly -ParameterFilter { $HostName -eq 'some.test.example' -and $AddressFamily -eq 'IPv4' }
            }
        }

        Describe 'Get-CertToolboxPlatform' {
            It 'names the platform this runs on' {
                $expected = 'Windows'
                if ((Get-Variable -Name 'IsMacOS' -ValueOnly -ErrorAction SilentlyContinue)) {
                    $expected = 'MacOS'
                } elseif ((Get-Variable -Name 'IsLinux' -ValueOnly -ErrorAction SilentlyContinue)) {
                    $expected = 'Linux'
                }

                Get-CertToolboxPlatform | Should -BeExactly $expected
                if ($PSVersionTable.PSVersion.Major -lt 6) {
                    Get-CertToolboxPlatform | Should -BeExactly 'Windows'
                }
            }
        }

        Describe 'Resolve-CertToolboxHostAddress' {
            It 'returns an IP address given in place of a name as is' {
                $addresses = @(Resolve-CertToolboxHostAddress -HostName '192.0.2.10')

                $addresses.Count | Should -Be 1
                $addresses[0] | Should -BeOfType [System.Net.IPAddress]
                $addresses[0].ToString() | Should -Be '192.0.2.10'
            }

            It 'keeps only the family asked for, and throws when there is none of it' {
                (Resolve-CertToolboxHostAddress -HostName '192.0.2.10' -AddressFamily IPv4).ToString() | Should -Be '192.0.2.10'
                (Resolve-CertToolboxHostAddress -HostName '2001:db8::1' -AddressFamily IPv6).ToString() | Should -Be '2001:db8::1'

                { Resolve-CertToolboxHostAddress -HostName '192.0.2.10' -AddressFamily IPv6 } | Should -Throw "*has no IPv6 address*"
                { Resolve-CertToolboxHostAddress -HostName '2001:db8::1' -AddressFamily IPv4 } | Should -Throw "*has no IPv4 address*"
            }
        }

        Describe 'Get-CertToolboxProbeTarget' {
            BeforeEach {
                Mock Resolve-CertToolboxHostAddress {
                    [System.Net.IPAddress]::Parse('192.0.2.10')
                    [System.Net.IPAddress]::Parse('192.0.2.11')
                    [System.Net.IPAddress]::Parse('2001:db8::1')
                } -ParameterFilter { $HostName -eq 'many.test.example' }
                Mock Resolve-CertToolboxHostAddress { throw [System.Net.Sockets.SocketException]::new([int][System.Net.Sockets.SocketError]::HostNotFound) } -ParameterFilter { $HostName -eq 'gone.test.example' }
            }

            It 'gives one target per name, unresolved, by default' {
                $targets = @(Get-CertToolboxProbeTarget -HostName 'many.test.example', 'other.test.example')

                $targets.Count | Should -Be 2
                ($targets.HostName -join ',') | Should -Be 'many.test.example,other.test.example'
                @($targets | Where-Object { $null -ne $_.Address }) | Should -BeNullOrEmpty
                ($targets.Label -join ',') | Should -Be 'many.test.example,other.test.example'
                Should -Invoke Resolve-CertToolboxHostAddress -Times 0 -Exactly
            }

            It 'gives one target per address with EveryAddress, labelled with the address' {
                $targets = @(Get-CertToolboxProbeTarget -HostName 'many.test.example' -EveryAddress)

                $targets.Count | Should -Be 3
                # Not $targets.Address: on an array that is the array's own Address method.
                (($targets | ForEach-Object { $_.Address }) -join ',') | Should -Be '192.0.2.10,192.0.2.11,2001:db8::1'
                $targets[0].Address | Should -BeOfType [System.Net.IPAddress]
                $targets[0].Label | Should -Be 'many.test.example [192.0.2.10]'
                @($targets | Where-Object HostName -ne 'many.test.example') | Should -BeNullOrEmpty
                @($targets | Where-Object Error) | Should -BeNullOrEmpty
            }

            It 'passes the address family to the resolution only when one is given' {
                Get-CertToolboxProbeTarget -HostName 'many.test.example' -EveryAddress -AddressFamily IPv6 | Out-Null
                Should -Invoke Resolve-CertToolboxHostAddress -Times 1 -Exactly -ParameterFilter { $AddressFamily -eq 'IPv6' }

                Get-CertToolboxProbeTarget -HostName 'many.test.example' -EveryAddress | Out-Null
                Should -Invoke Resolve-CertToolboxHostAddress -Times 1 -Exactly -ParameterFilter { -not $AddressFamily }
            }

            It 'gives a target carrying the error for a name that does not resolve, and still gives the others' {
                $targets = @(Get-CertToolboxProbeTarget -HostName 'gone.test.example', 'many.test.example' -EveryAddress)

                $targets.Count | Should -Be 4
                $targets[0].HostName | Should -Be 'gone.test.example'
                $targets[0].Error | Should -BeOfType [System.Net.Sockets.SocketException]
                $targets[0].Address | Should -BeNullOrEmpty
                @($targets | Select-Object -Skip 1 | Where-Object Error) | Should -BeNullOrEmpty
            }
        }

        Describe 'Invoke-CertToolboxTlsHandshake' {
            It 'fails within the socket timeout when the server never answers' {
                $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
                $listener.Start()
                $client = $null
                try {
                    $client = Connect-CertToolboxTcpClient -HostName '127.0.0.1' -Port $listener.LocalEndpoint.Port -TimeoutMs 1500
                    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

                    { Invoke-CertToolboxTlsHandshake -Stream $client.GetStream() -TargetHost 'localhost' } | Should -Throw

                    $stopwatch.Stop()
                    $stopwatch.ElapsedMilliseconds | Should -BeGreaterThan 1000
                    $stopwatch.ElapsedMilliseconds | Should -BeLessThan 6000
                } finally {
                    if ($client) { $client.Close() }
                    $listener.Stop()
                }
            }
        }

        Describe 'Invoke-CertToolboxTlsProbe' {
            BeforeEach {
                $script:fakeClient = [System.Net.Sockets.TcpClient]::new()
                Mock Connect-CertToolboxTcpClient { $script:fakeClient }
            }

            It 'unwraps a connection failure to its innermost exception' {
                Mock Connect-CertToolboxTcpClient {
                    throw [System.Exception]::new('wrapper', [System.TimeoutException]::new('connect timed out'))
                }

                { Invoke-CertToolboxTlsProbe -HostName 'host.example' -Port 443 } |
                    Should -Throw -ExceptionType ([System.TimeoutException])
            }

            It 'passes a chosen address and an address family to the connection, and neither by default' {
                Mock Connect-CertToolboxTcpClient { throw [System.TimeoutException]::new('stop here') }

                { Invoke-CertToolboxTlsProbe -HostName 'host.example' -Port 443 -Address ([System.Net.IPAddress]::Parse('192.0.2.10')) -AddressFamily IPv4 } | Should -Throw 'stop here'
                Should -Invoke Connect-CertToolboxTcpClient -Times 1 -Exactly -ParameterFilter { "$Address" -eq '192.0.2.10' -and $AddressFamily -eq 'IPv4' }

                { Invoke-CertToolboxTlsProbe -HostName 'host.example' -Port 443 } | Should -Throw 'stop here'
                Should -Invoke Connect-CertToolboxTcpClient -Times 1 -Exactly -ParameterFilter { $null -eq $Address -and -not $AddressFamily }
            }

            It 'defaults the target host to the host name and passes the options through' {
                Mock Connect-CertToolboxTcpClient {
                    throw [System.TimeoutException]::new('stop here')
                } -ParameterFilter { $HostName -eq 'host.example' -and $Port -eq 8443 -and $TimeoutMs -eq 2500 }

                { Invoke-CertToolboxTlsProbe -HostName 'host.example' -Port 8443 -TimeoutMs 2500 } | Should -Throw 'stop here'
            }
        }
    }
}

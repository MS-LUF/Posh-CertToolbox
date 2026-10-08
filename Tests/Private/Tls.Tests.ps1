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

            It 'defaults the target host to the host name and passes the options through' {
                Mock Connect-CertToolboxTcpClient {
                    throw [System.TimeoutException]::new('stop here')
                } -ParameterFilter { $HostName -eq 'host.example' -and $Port -eq 8443 -and $TimeoutMs -eq 2500 }

                { Invoke-CertToolboxTlsProbe -HostName 'host.example' -Port 8443 -TimeoutMs 2500 } | Should -Throw 'stop here'
            }
        }
    }
}

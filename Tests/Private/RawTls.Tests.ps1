BeforeDiscovery {
    Import-Module (Join-Path $PSScriptRoot '../../Posh-CertToolbox.psd1') -Force
}

Describe 'Private/RawTls' -Tag Unit {
    InModuleScope 'Posh-CertToolbox' {
        BeforeAll {
            . (Join-Path $PSScriptRoot '../TestHelper.ps1')
            $script:chain = Get-TestCertificateChain

            # A complete first flight of a TLS 1.2 server, as records.
            $script:helloDone = ConvertTo-TestHandshakeMessage -Type 14
            $script:keyExchangeP256 = ConvertTo-TestHandshakeMessage -Type 12 -Body ([byte[]](3, 0, 23, 4, 1, 2, 3, 4))
        }

        Describe 'Cipher suite registry' {
            It 'holds the whole registry, without signalling values' {
                $script:CertToolboxCipherSuiteName.Count | Should -BeGreaterThan 340
                $script:CertToolboxCipherSuiteName[0xC02F] | Should -Be 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
                $script:CertToolboxCipherSuiteName[0x0005] | Should -Be 'TLS_RSA_WITH_RC4_128_SHA'
                $script:CertToolboxCipherSuiteName[0x1301] | Should -Be 'TLS_AES_128_GCM_SHA256'
                $script:CertToolboxCipherSuiteName[0x0000] | Should -Be 'TLS_NULL_WITH_NULL_NULL'
                # TLS_EMPTY_RENEGOTIATION_INFO_SCSV and TLS_FALLBACK_SCSV are not cipher suites.
                $script:CertToolboxCipherSuiteName.ContainsKey(0x00FF) | Should -BeFalse
                $script:CertToolboxCipherSuiteName.ContainsKey(0x5600) | Should -BeFalse
                @($script:CertToolboxCipherSuiteName.Values | Where-Object { $_ -notmatch '^TLS_' -or $_ -match '_SCSV$' }) | Should -BeNullOrEmpty
            }

            It 'separates the TLS 1.3 suites from the earlier ones, with nothing in both or neither' {
                $script:CertToolboxTls13CipherSuite | Should -Contain 0x1301
                $script:CertToolboxTls13CipherSuite | Should -Contain 0x1303
                $script:CertToolboxTls13CipherSuite | Should -Not -Contain 0xC02F
                $script:CertToolboxLegacyCipherSuite | Should -Contain 0xC02F
                $script:CertToolboxLegacyCipherSuite | Should -Contain 0x0005
                $script:CertToolboxLegacyCipherSuite | Should -Not -Contain 0x1301

                $script:CertToolboxLegacyCipherSuite.Count + $script:CertToolboxTls13CipherSuite.Count |
                    Should -Be $script:CertToolboxCipherSuiteName.Count
            }
        }

        Describe 'Get-CertToolboxCipherSuiteInfo' {
            It 'describes <Name>' -ForEach @(
                @{ Code = 0xC02F; Name = 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'; Fs = $true; Aead = $true; Weak = $false }
                @{ Code = 0xC013; Name = 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA'; Fs = $true; Aead = $false; Weak = $false }
                @{ Code = 0x009C; Name = 'TLS_RSA_WITH_AES_128_GCM_SHA256'; Fs = $false; Aead = $true; Weak = $false }
                @{ Code = 0x009E; Name = 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256'; Fs = $true; Aead = $true; Weak = $false }
                @{ Code = 0xCCA8; Name = 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256'; Fs = $true; Aead = $true; Weak = $false }
                @{ Code = 0x1301; Name = 'TLS_AES_128_GCM_SHA256'; Fs = $true; Aead = $true; Weak = $false }
                @{ Code = 0x0005; Name = 'TLS_RSA_WITH_RC4_128_SHA'; Fs = $false; Aead = $false; Weak = $true }
                @{ Code = 0x0004; Name = 'TLS_RSA_WITH_RC4_128_MD5'; Fs = $false; Aead = $false; Weak = $true }
                @{ Code = 0x000A; Name = 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'; Fs = $false; Aead = $false; Weak = $true }
                @{ Code = 0x0009; Name = 'TLS_RSA_WITH_DES_CBC_SHA'; Fs = $false; Aead = $false; Weak = $true }
                @{ Code = 0x0008; Name = 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA'; Fs = $false; Aead = $false; Weak = $true }
                @{ Code = 0x003B; Name = 'TLS_RSA_WITH_NULL_SHA256'; Fs = $false; Aead = $false; Weak = $true }
                @{ Code = 0x00A6; Name = 'TLS_DH_anon_WITH_AES_128_GCM_SHA256'; Fs = $false; Aead = $true; Weak = $true }
                @{ Code = 0xC0B4; Name = 'TLS_SHA256_SHA256'; Fs = $true; Aead = $false; Weak = $true }
            ) {
                $info = Get-CertToolboxCipherSuiteInfo -Code $Code

                $info.Name | Should -Be $Name
                $info.Code | Should -Be ('0x{0:X4}' -f $Code)
                $info.ForwardSecrecy | Should -Be $Fs
                $info.AuthenticatedEncryption | Should -Be $Aead
                $info.Weak | Should -Be $Weak
            }

            It 'names an unregistered code by its number and states nothing about it' {
                $info = Get-CertToolboxCipherSuiteInfo -Code 0xFEFE

                $info.Name | Should -Be '0xFEFE'
                $info.Weak | Should -BeNullOrEmpty
                $info.ForwardSecrecy | Should -BeNullOrEmpty
            }
        }

        Describe 'ConvertTo-CertToolboxClientHello' {
            It 'builds a well-formed TLS 1.2 hello with exactly the suites and groups asked for' {
                $bytes = ConvertTo-CertToolboxClientHello -Protocol Tls12 -CipherSuite 0xC02F, 0x009C, 0x0005 -ServerName 'www.test.example' -Group 29, 23
                $hello = ConvertFrom-TestClientHello -Bytes $bytes

                , $bytes | Should -BeOfType [byte[]]
                $hello.RecordType | Should -Be 22
                $hello.RecordVersion | Should -Be 0x0301
                $hello.RecordLength | Should -Be ($bytes.Length - 5)
                $hello.HandshakeType | Should -Be 1
                $hello.HandshakeLength | Should -Be ($bytes.Length - 9)
                $hello.ClientVersion | Should -Be 0x0303
                $hello.SessionIdLength | Should -Be 0
                ($hello.CipherSuite -join ',') | Should -Be '49199,156,5'
                $hello.ExtensionEnd | Should -Be $bytes.Length

                # server name: list length, type 0, name length, name
                [System.Text.Encoding]::ASCII.GetString($hello.Extension['0'], 5, $hello.Extension['0'].Length - 5) | Should -Be 'www.test.example'
                [System.BitConverter]::ToString($hello.Extension['10']) | Should -Be '00-04-00-1D-00-17'
                $hello.Extension.Contains('13') | Should -BeTrue
                [System.BitConverter]::ToString($hello.Extension['5']) | Should -Be '01-00-00-00-00'
                $hello.Extension.Contains('23') | Should -BeTrue
                $hello.Extension.Contains('65281') | Should -BeTrue
                $hello.Extension.Contains('43') | Should -BeFalse
                $hello.Extension.Contains('51') | Should -BeFalse
            }

            It 'gives each older version its own number' -ForEach @(
                @{ Protocol = 'Tls'; Version = 0x0301 }, @{ Protocol = 'Tls11'; Version = 0x0302 }
            ) {
                $hello = ConvertFrom-TestClientHello -Bytes (ConvertTo-CertToolboxClientHello -Protocol $Protocol -CipherSuite 0x002F -ServerName 'a.example' -Group 23)

                $hello.ClientVersion | Should -Be $Version
            }

            It 'sends an SSL 3.0 hello with no extension at all' {
                $bytes = ConvertTo-CertToolboxClientHello -Protocol Ssl3 -CipherSuite 0x0005, 0x000A -ServerName 'a.example' -Group 23
                $hello = ConvertFrom-TestClientHello -Bytes $bytes

                $hello.RecordVersion | Should -Be 0x0300
                $hello.ClientVersion | Should -Be 0x0300
                $hello.Extension.Count | Should -Be 0
                $hello.RecordLength | Should -Be ($bytes.Length - 5)
            }

            It 'announces TLS 1.3 through extensions, with an x25519 key share when that group is offered' {
                $hello = ConvertFrom-TestClientHello -Bytes (ConvertTo-CertToolboxClientHello -Protocol Tls13 -CipherSuite 0x1301, 0x1302 -ServerName 'a.example' -Group 29, 23)

                $hello.ClientVersion | Should -Be 0x0303
                $hello.SessionIdLength | Should -Be 32
                [System.BitConverter]::ToString($hello.Extension['43']) | Should -Be '02-03-04'
                [System.BitConverter]::ToString($hello.Extension['45']) | Should -Be '01-01'
                # shares length (2) + group (2) + key length (2) + 32 key bytes
                $hello.Extension['51'].Length | Should -Be 38
                [System.BitConverter]::ToString($hello.Extension['51'], 0, 6) | Should -Be '00-24-00-1D-00-20'
            }

            It 'sends an empty key share list when x25519 is not offered, so the server has to name its group' {
                $hello = ConvertFrom-TestClientHello -Bytes (ConvertTo-CertToolboxClientHello -Protocol Tls13 -CipherSuite 0x1301 -ServerName 'a.example' -Group 24)

                [System.BitConverter]::ToString($hello.Extension['51']) | Should -Be '00-00'
            }

            It 'does not send a server name for an IP address' {
                $hello = ConvertFrom-TestClientHello -Bytes (ConvertTo-CertToolboxClientHello -Protocol Tls12 -CipherSuite 0xC02F -ServerName '192.0.2.10' -Group 23)

                $hello.Extension.Contains('0') | Should -BeFalse
                $hello.Extension.Contains('10') | Should -BeTrue
            }

            It 'can offer the whole registry in one hello' {
                $bytes = ConvertTo-CertToolboxClientHello -Protocol Tls12 -CipherSuite $script:CertToolboxLegacyCipherSuite -ServerName 'a.example' -Group $script:CertToolboxLegacyProbeGroup
                $hello = ConvertFrom-TestClientHello -Bytes $bytes

                $hello.CipherSuite.Count | Should -Be $script:CertToolboxLegacyCipherSuite.Count
                $hello.HandshakeLength | Should -Be ($bytes.Length - 9)
                $hello.ExtensionEnd | Should -Be $bytes.Length
            }
        }

        Describe 'Read-CertToolboxTlsRecord' {
            It 'reads records one at a time' {
                $stream = [System.IO.MemoryStream]::new([byte[]]((ConvertTo-TestTlsRecord -Type 22 -Payload ([byte[]](1, 2, 3))) + (ConvertTo-TestTlsRecord -Type 21 -Payload ([byte[]](2, 40)))))

                $first = Read-CertToolboxTlsRecord -Stream $stream
                $first.Type | Should -Be 22
                ($first.Payload -join ',') | Should -Be '1,2,3'
                $second = Read-CertToolboxTlsRecord -Stream $stream
                $second.Type | Should -Be 21
                ($second.Payload -join ',') | Should -Be '2,40'
            }

            It 'reads a record longer than 255 bytes' {
                $stream = [System.IO.MemoryStream]::new((ConvertTo-TestTlsRecord -Type 22 -Payload (New-Object byte[] 5000)))

                (Read-CertToolboxTlsRecord -Stream $stream).Payload.Length | Should -Be 5000
            }

            It 'throws when the server closes the connection, before or inside a record' {
                { Read-CertToolboxTlsRecord -Stream ([System.IO.MemoryStream]::new()) } | Should -Throw -ExceptionType ([System.IO.EndOfStreamException])

                $truncated = [byte[]](22, 3, 3, 0, 10, 1, 2)
                { Read-CertToolboxTlsRecord -Stream ([System.IO.MemoryStream]::new($truncated)) } | Should -Throw -ExceptionType ([System.IO.EndOfStreamException])
            }

            It 'throws when the answer is not TLS' {
                $http = [System.Text.Encoding]::ASCII.GetBytes("HTTP/1.1 400 Bad Request`r`n`r`n")

                { Read-CertToolboxTlsRecord -Stream ([System.IO.MemoryStream]::new($http)) } | Should -Throw '*did not answer with a TLS record*'
            }
        }

        Describe 'ConvertFrom-CertToolboxServerHello' {
            It 'reads the version, the suite and the acknowledged extensions of a TLS 1.2 hello' {
                $body = Get-TestServerHelloBody -Version 0x0303 -CipherSuite 0xC030 -Extension ([ordered]@{ 23 = [byte[]]@(); 0xFF01 = [byte[]]@(0) })

                $hello = ConvertFrom-CertToolboxServerHello -Bytes $body -Offset 0 -Length $body.Length

                $hello.Version | Should -Be 0x0303
                $hello.CipherSuite | Should -Be 0xC030
                $hello.ExtendedMasterSecret | Should -BeTrue
                $hello.SecureRenegotiation | Should -BeTrue
                $hello.HelloRetryRequest | Should -BeFalse
                $hello.Group | Should -BeNullOrEmpty
            }

            It 'reads a hello without any extension' {
                $body = Get-TestServerHelloBody -Version 0x0301 -CipherSuite 0x0005

                $hello = ConvertFrom-CertToolboxServerHello -Bytes $body -Offset 0 -Length $body.Length

                $hello.Version | Should -Be 0x0301
                $hello.CipherSuite | Should -Be 0x0005
                $hello.SecureRenegotiation | Should -BeFalse
            }

            It 'takes the TLS 1.3 version and the group from the extensions' {
                $body = Get-TestServerHelloBody -Version 0x0303 -CipherSuite 0x1302 -Extension ([ordered]@{ 43 = [byte[]](3, 4); 51 = [byte[]](0, 29, 0, 2, 9, 9) })

                $hello = ConvertFrom-CertToolboxServerHello -Bytes $body -Offset 0 -Length $body.Length

                $hello.Version | Should -Be 0x0304
                $hello.CipherSuite | Should -Be 0x1302
                $hello.Group | Should -Be 29
                $hello.HelloRetryRequest | Should -BeFalse
            }

            It 'recognises a HelloRetryRequest and the group it asks for' {
                $body = Get-TestServerHelloBody -HelloRetryRequest -CipherSuite 0x1301 -Extension ([ordered]@{ 43 = [byte[]](3, 4); 51 = [byte[]](0, 23) })

                $hello = ConvertFrom-CertToolboxServerHello -Bytes $body -Offset 0 -Length $body.Length

                $hello.HelloRetryRequest | Should -BeTrue
                $hello.Group | Should -Be 23
            }

            It 'decodes a message that sits at an offset inside a larger buffer' {
                $body = Get-TestServerHelloBody -CipherSuite 0xC02B
                $buffer = [byte[]](@(9, 9, 9, 9) + $body + @(7, 7))

                (ConvertFrom-CertToolboxServerHello -Bytes $buffer -Offset 4 -Length $body.Length).CipherSuite | Should -Be 0xC02B
            }

            It 'throws on a truncated message' {
                { ConvertFrom-CertToolboxServerHello -Bytes ([byte[]](3, 3, 1, 2)) -Offset 0 -Length 4 } | Should -Throw
            }
        }

        Describe 'Read-CertToolboxServerFlight' {
            It 'reads a whole TLS 1.2 flight: hello, chain as sent, stapled status, curve' {
                $hello = ConvertTo-TestHandshakeMessage -Type 2 -Body (Get-TestServerHelloBody -CipherSuite 0xC02F -Extension ([ordered]@{ 0xFF01 = [byte[]]@(0) }))
                # Sent in an unusual order on purpose: the order on the wire is what is reported.
                $certificate = ConvertTo-TestHandshakeMessage -Type 11 -Body (Get-TestCertificateMessageBody -Certificate $script:chain.Leaf, $script:chain.Root, $script:chain.Intermediate)
                $status = ConvertTo-TestHandshakeMessage -Type 22 -Body ([byte[]](1, 0, 0, 1, 0x30))
                $bytes = [byte[]]((ConvertTo-TestTlsRecord -Type 22 -Payload $hello) + (ConvertTo-TestTlsRecord -Type 22 -Payload $certificate) +
                    (ConvertTo-TestTlsRecord -Type 22 -Payload ([byte[]]($status + $script:keyExchangeP256 + $script:helloDone))))

                $flight = Read-CertToolboxServerFlight -Stream ([System.IO.MemoryStream]::new($bytes))

                $flight.ServerHello | Should -BeTrue
                $flight.Version | Should -Be 0x0303
                $flight.CipherSuite | Should -Be 0xC02F
                $flight.SecureRenegotiation | Should -BeTrue
                $flight.ExtendedMasterSecret | Should -BeFalse
                $flight.OcspStapled | Should -BeTrue
                $flight.Group | Should -Be 23
                $flight.Complete | Should -BeTrue
                $flight.Alert | Should -BeNullOrEmpty
                ($flight.Certificate.Thumbprint -join ',') | Should -Be ($script:chain.Leaf.Thumbprint, $script:chain.Root.Thumbprint, $script:chain.Intermediate.Thumbprint -join ',')
            }

            It 'reassembles a message split across records' {
                $hello = ConvertTo-TestHandshakeMessage -Type 2 -Body (Get-TestServerHelloBody -CipherSuite 0x009C)
                $certificate = ConvertTo-TestHandshakeMessage -Type 11 -Body (Get-TestCertificateMessageBody -Certificate $script:chain.Leaf, $script:chain.Intermediate)
                $all = [byte[]]($hello + $certificate + $script:helloDone)
                # Cut in the middle of the ServerHello and again in the middle of the certificates.
                $cuts = 20, 400, ($all.Length - 2)
                $bytes = [byte[]]@()
                $start = 0
                foreach ($cut in ($cuts + $all.Length)) {
                    $bytes = [byte[]]($bytes + (ConvertTo-TestTlsRecord -Type 22 -Payload ([byte[]]$all[$start..($cut - 1)])))
                    $start = $cut
                }

                $flight = Read-CertToolboxServerFlight -Stream ([System.IO.MemoryStream]::new($bytes))

                $flight.CipherSuite | Should -Be 0x009C
                $flight.Certificate.Count | Should -Be 2
                $flight.OcspStapled | Should -BeFalse
                $flight.Group | Should -BeNullOrEmpty
                $flight.Complete | Should -BeTrue
            }

            It 'returns the alert when the server refuses' {
                $bytes = ConvertTo-TestTlsRecord -Type 21 -Payload ([byte[]](2, 40))
                $flight = Read-CertToolboxServerFlight -Stream ([System.IO.MemoryStream]::new($bytes))
                $flight.ServerHello | Should -BeFalse
                $flight.Alert | Should -Be 'handshake_failure'

                $bytes = ConvertTo-TestTlsRecord -Type 21 -Payload ([byte[]](2, 70))
                (Read-CertToolboxServerFlight -Stream ([System.IO.MemoryStream]::new($bytes))).Alert | Should -Be 'protocol_version'

                $bytes = ConvertTo-TestTlsRecord -Type 21 -Payload ([byte[]](2, 199))
                (Read-CertToolboxServerFlight -Stream ([System.IO.MemoryStream]::new($bytes))).Alert | Should -Be 'alert_199'
            }

            It 'stops after the ServerHello of TLS 1.3, without reading the encrypted rest' {
                $hello = ConvertTo-TestHandshakeMessage -Type 2 -Body (Get-TestServerHelloBody -CipherSuite 0x1301 -Extension ([ordered]@{ 43 = [byte[]](3, 4); 51 = [byte[]](0, 29, 0, 1, 5) }))
                $bytes = [byte[]]((ConvertTo-TestTlsRecord -Type 22 -Payload $hello) + (ConvertTo-TestTlsRecord -Type 20 -Payload ([byte[]]@(1))) +
                    (ConvertTo-TestTlsRecord -Type 23 -Payload (New-Object byte[] 64)))
                $stream = [System.IO.MemoryStream]::new($bytes)

                $flight = Read-CertToolboxServerFlight -Stream $stream

                $flight.Version | Should -Be 0x0304
                $flight.CipherSuite | Should -Be 0x1301
                $flight.Group | Should -Be 29
                $flight.Complete | Should -BeTrue
                # The change cipher spec and the encrypted record were left unread.
                $stream.Position | Should -Be (5 + $hello.Length)
            }

            It 'keeps what it read, marked incomplete, when the connection fails after the ServerHello' {
                $hello = ConvertTo-TestHandshakeMessage -Type 2 -Body (Get-TestServerHelloBody -CipherSuite 0xC02F -Extension ([ordered]@{ 23 = [byte[]]@() }))
                $bytes = ConvertTo-TestTlsRecord -Type 22 -Payload $hello

                $flight = Read-CertToolboxServerFlight -Stream ([System.IO.MemoryStream]::new($bytes))

                $flight.ServerHello | Should -BeTrue
                $flight.CipherSuite | Should -Be 0xC02F
                $flight.ExtendedMasterSecret | Should -BeTrue
                $flight.Complete | Should -BeFalse
            }

            It 'throws when the connection fails before any ServerHello, or the answer is not TLS' {
                { Read-CertToolboxServerFlight -Stream ([System.IO.MemoryStream]::new()) } | Should -Throw -ExceptionType ([System.IO.EndOfStreamException])

                $smtp = [System.Text.Encoding]::ASCII.GetBytes("220 mail.test.example ESMTP`r`n")
                { Read-CertToolboxServerFlight -Stream ([System.IO.MemoryStream]::new($smtp)) } | Should -Throw '*did not answer with a TLS record*'
            }
        }

        # A real loopback socket whose server side has already sent its flight: this exercises
        # the real connect, send and receive path, offline.
        Describe 'Invoke-CertToolboxRawHello' {
            AfterEach {
                if ($script:connection) {
                    Close-TestScriptedConnection -Connection $script:connection
                    $script:connection = $null
                }
            }

            It 'sends the hello on the connection and returns the decoded answer' {
                $hello = ConvertTo-TestHandshakeMessage -Type 2 -Body (Get-TestServerHelloBody -CipherSuite 0xC030)
                $certificate = ConvertTo-TestHandshakeMessage -Type 11 -Body (Get-TestCertificateMessageBody -Certificate $script:chain.Leaf)
                $script:connection = Get-TestScriptedConnection -ServerByte (ConvertTo-TestTlsRecord -Type 22 -Payload ([byte[]]($hello + $certificate + $script:helloDone)))
                Mock Connect-CertToolboxTcpClient { $script:connection.Client }

                $answer = Invoke-CertToolboxRawHello -HostName '127.0.0.1' -Port 4433 -TargetHost 'www.test.example' -Protocol Tls12 -CipherSuite 0xC030, 0xC02F -Group 23 -TimeoutMs 2500

                $answer.ServerHello | Should -BeTrue
                $answer.CipherSuite | Should -Be 0xC030
                $answer.Certificate.Count | Should -Be 1
                $answer.RemoteAddress | Should -Be '127.0.0.1'
                $answer.Error | Should -BeNullOrEmpty
                $answer.Stage | Should -BeNullOrEmpty
                Should -Invoke Connect-CertToolboxTcpClient -Times 1 -Exactly -ParameterFilter { $HostName -eq '127.0.0.1' -and $Port -eq 4433 -and $TimeoutMs -eq 2500 }

                # What the client actually sent: a ClientHello naming the target host.
                Start-Sleep -Milliseconds 100
                $sent = New-Object byte[] $script:connection.Server.Available
                $null = $script:connection.Server.GetStream().Read($sent, 0, $sent.Length)
                $clientHello = ConvertFrom-TestClientHello -Bytes $sent
                $clientHello.TotalLength | Should -Be ($clientHello.RecordLength + 5)
                ($clientHello.CipherSuite -join ',') | Should -Be '49200,49199'
                [System.Text.Encoding]::ASCII.GetString($clientHello.Extension['0'], 5, $clientHello.Extension['0'].Length - 5) | Should -Be 'www.test.example'
            }

            It 'reports a failure to connect as such, without throwing' {
                Mock Connect-CertToolboxTcpClient { throw [System.Net.Sockets.SocketException]::new([int][System.Net.Sockets.SocketError]::ConnectionRefused) }

                $answer = Invoke-CertToolboxRawHello -HostName 'down.test.example' -Port 443 -Protocol Tls12 -CipherSuite 0xC030

                $answer.ServerHello | Should -BeFalse
                $answer.Stage | Should -Be 'Connect'
                $answer.Error | Should -Not -BeNullOrEmpty
            }

            It 'passes a chosen address and an address family to the connection' {
                Mock Connect-CertToolboxTcpClient { throw [System.TimeoutException]::new('stop here') }

                $answer = Invoke-CertToolboxRawHello -HostName 'host.test.example' -Port 443 -Protocol Tls12 -CipherSuite 0xC030 `
                    -Address ([System.Net.IPAddress]::Parse('2001:db8::1')) -AddressFamily IPv6

                $answer.Stage | Should -Be 'Connect'
                Should -Invoke Connect-CertToolboxTcpClient -Times 1 -Exactly -ParameterFilter { "$Address" -eq '2001:db8::1' -and $AddressFamily -eq 'IPv6' }
            }

            It 'reports an answer that is not TLS as a handshake failure' {
                $script:connection = Get-TestScriptedConnection -ServerLine 'HTTP/1.1 400 Bad Request', ''
                Mock Connect-CertToolboxTcpClient { $script:connection.Client }

                $answer = Invoke-CertToolboxRawHello -HostName '127.0.0.1' -Port 80 -Protocol Tls12 -CipherSuite 0xC030

                $answer.ServerHello | Should -BeFalse
                $answer.Stage | Should -Be 'Handshake'
                $answer.Error | Should -BeLike '*did not answer with a TLS record*'
            }

            It 'runs the plaintext upgrade first, and reports its failure as a connect failure' {
                $script:order = [System.Collections.Generic.List[string]]::new()
                $hello = ConvertTo-TestHandshakeMessage -Type 2 -Body (Get-TestServerHelloBody -Version 0x0303 -CipherSuite 0x1301 -Extension ([ordered]@{ 43 = [byte[]](3, 4) }))
                $script:connection = Get-TestScriptedConnection -ServerByte (ConvertTo-TestTlsRecord -Type 22 -Payload $hello)
                Mock Connect-CertToolboxTcpClient { $script:connection.Client }
                Mock Invoke-CertToolboxStartTls { $script:order.Add('starttls') }

                $answer = Invoke-CertToolboxRawHello -HostName '127.0.0.1' -Port 25 -Protocol Tls13 -CipherSuite 0x1301 -Group 29 -StartTls Smtp -SmtpEhloName 'client.example'

                $answer.Version | Should -Be 0x0304
                Should -Invoke Invoke-CertToolboxStartTls -Times 1 -Exactly -ParameterFilter { $StartTls -eq 'Smtp' -and $SmtpEhloName -eq 'client.example' }

                Close-TestScriptedConnection -Connection $script:connection
                $script:connection = Get-TestScriptedConnection
                Mock Invoke-CertToolboxStartTls { throw [System.Net.ProtocolViolationException]::new('The SMTP server does not advertise STARTTLS in its EHLO reply.') }
                $refused = Invoke-CertToolboxRawHello -HostName '127.0.0.1' -Port 25 -Protocol Tls12 -CipherSuite 0xC030 -StartTls Smtp
                $refused.Stage | Should -Be 'Connect'
                $refused.Error | Should -BeLike '*does not advertise STARTTLS*'
            }
        }

        Describe 'Find-CertToolboxServerCipherSuite' {
            BeforeEach {
                # A model server: it accepts these suites for these versions, in this order of
                # preference, and either imposes that order or follows the client's.
                $script:server = @{
                    Version      = 0x0303
                    Preference   = [int[]](0xC030, 0xC02F, 0x009C, 0x0005)
                    ImposesOrder = $true
                    Calls        = 0
                }
                Mock Invoke-CertToolboxRawHello {
                    $script:server.Calls++
                    $choice = $null
                    if ($script:server.ImposesOrder) {
                        $choice = $script:server.Preference | Where-Object { $CipherSuite -contains $_ } | Select-Object -First 1
                    } else {
                        $choice = $CipherSuite | Where-Object { $script:server.Preference -contains $_ } | Select-Object -First 1
                    }
                    if ($null -eq $choice) {
                        return [PSCustomObject]@{ ServerHello = $false; Alert = 'handshake_failure'; Error = $null; Stage = $null }
                    }
                    [PSCustomObject]@{ ServerHello = $true; Version = $script:server.Version; CipherSuite = [int]$choice; Alert = $null; Error = $null; Stage = $null; Marker = $script:server.Calls }
                }
                $script:connectionSettings = @{ HostName = 'server.test.example'; Port = 8443; TimeoutMs = 3000 }
            }

            It 'finds every accepted suite in the order the server picks them' {
                $found = Find-CertToolboxServerCipherSuite -Connection $script:connectionSettings -Protocol Tls12

                $found.Accepted | Should -BeTrue
                $found.Reason | Should -BeNullOrEmpty
                ($found.CipherSuite -join ',') | Should -Be (0xC030, 0xC02F, 0x009C, 0x0005 -join ',')
                $found.ServerCipherOrder | Should -BeTrue
                $found.FirstAnswer.Marker | Should -Be 1
                $found.ConnectFailed | Should -BeFalse
                # four accepted, one refused, one for the order check
                $found.ConnectionCount | Should -Be 6
                Should -Invoke Invoke-CertToolboxRawHello -Times 6 -Exactly -ParameterFilter { $HostName -eq 'server.test.example' -and $Port -eq 8443 -and $TimeoutMs -eq 3000 -and $Protocol -eq 'Tls12' }
            }

            It 'offers the whole registry first, and never a TLS 1.3 suite to an earlier version' {
                Find-CertToolboxServerCipherSuite -Connection $script:connectionSettings -Protocol Tls12 | Out-Null

                Should -Invoke Invoke-CertToolboxRawHello -Times 1 -Exactly -ParameterFilter { $CipherSuite.Count -eq $script:CertToolboxLegacyCipherSuite.Count }
                Should -Invoke Invoke-CertToolboxRawHello -Times 0 -Exactly -ParameterFilter { $CipherSuite -contains 0x1301 }
            }

            It 'detects a server that follows the client order' {
                $script:server.ImposesOrder = $false

                $found = Find-CertToolboxServerCipherSuite -Connection $script:connectionSettings -Protocol Tls12

                $found.CipherSuite.Count | Should -Be 4
                $found.ServerCipherOrder | Should -BeFalse
            }

            It 'cannot tell the order with a single suite, and does not spend a connection on it' {
                $script:server.Preference = [int[]](0xC030)

                $found = Find-CertToolboxServerCipherSuite -Connection $script:connectionSettings -Protocol Tls12

                ($found.CipherSuite -join ',') | Should -Be "$(0xC030)"
                $found.ServerCipherOrder | Should -BeNullOrEmpty
                $found.ConnectionCount | Should -Be 2
            }

            It 'offers only TLS 1.3 suites to TLS 1.3' {
                $script:server.Version = 0x0304
                $script:server.Preference = [int[]](0x1302, 0x1301)

                $found = Find-CertToolboxServerCipherSuite -Connection $script:connectionSettings -Protocol Tls13

                ($found.CipherSuite -join ',') | Should -Be (0x1302, 0x1301 -join ',')
                Should -Invoke Invoke-CertToolboxRawHello -Times 0 -Exactly -ParameterFilter { $CipherSuite -contains 0xC02F }
            }

            It 'reports the alert of a server that refuses the version' {
                $script:server.Preference = [int[]]@()

                $found = Find-CertToolboxServerCipherSuite -Connection $script:connectionSettings -Protocol Tls11

                $found.Accepted | Should -BeFalse
                $found.CipherSuite | Should -BeNullOrEmpty
                $found.Reason | Should -Be "The server refused with the alert 'handshake_failure'."
                $found.ConnectionCount | Should -Be 1
            }

            It 'does not count a version the server answers with another version' {
                # Asked for TLS 1.2, the server answers with TLS 1.1.
                $script:server.Version = 0x0302

                $found = Find-CertToolboxServerCipherSuite -Connection $script:connectionSettings -Protocol Tls12

                $found.Accepted | Should -BeFalse
                $found.Reason | Should -Be 'The server answered with Tls11 instead.'
            }

            It 'tells a connection failure from a refusal' {
                Mock Invoke-CertToolboxRawHello { [PSCustomObject]@{ ServerHello = $false; Alert = $null; Error = 'No such host is known.'; Stage = 'Connect' } }
                $unreachable = Find-CertToolboxServerCipherSuite -Connection $script:connectionSettings -Protocol Tls12
                $unreachable.Accepted | Should -BeFalse
                $unreachable.ConnectFailed | Should -BeTrue
                $unreachable.Reason | Should -Be 'No such host is known.'

                Mock Invoke-CertToolboxRawHello { [PSCustomObject]@{ ServerHello = $false; Alert = $null; Error = 'The server did not answer with a TLS record.'; Stage = 'Handshake' } }
                $notTls = Find-CertToolboxServerCipherSuite -Connection $script:connectionSettings -Protocol Tls12
                $notTls.ConnectFailed | Should -BeFalse
                $notTls.Reason | Should -BeLike '*TLS record*'
            }
        }

        Describe 'Find-CertToolboxServerGroup' {
            BeforeEach {
                $script:acceptedGroup = [int[]](23, 29)
                $script:connectionSettings = @{ HostName = 'server.test.example'; Port = 8443 }
            }

            It 'tries each TLS 1.3 group alone and keeps the ones the server takes up' {
                Mock Invoke-CertToolboxRawHello {
                    if ($script:acceptedGroup -contains $Group[0]) {
                        return [PSCustomObject]@{ ServerHello = $true; Version = 0x0304; Group = $Group[0]; Error = $null; Stage = $null }
                    }
                    [PSCustomObject]@{ ServerHello = $false; Alert = 'handshake_failure'; Error = $null; Stage = $null }
                }

                $result = Find-CertToolboxServerGroup -Connection $script:connectionSettings -Protocol Tls13 -CipherSuite 0x1301, 0x1302

                ($result.Group | Sort-Object) -join ',' | Should -Be '23,29'
                $result.ConnectionCount | Should -Be $script:CertToolboxTls13ProbeGroup.Count
                Should -Invoke Invoke-CertToolboxRawHello -Times 0 -Exactly -ParameterFilter { $Group.Count -ne 1 }
                Should -Invoke Invoke-CertToolboxRawHello -Times $script:CertToolboxTls13ProbeGroup.Count -Exactly -ParameterFilter { ($CipherSuite -join ',') -eq (0x1301, 0x1302 -join ',') }
            }

            It 'finds the curves of an earlier version in the server''s order, offering only its ECDHE suites' {
                # The server prefers P-256, then x25519.
                Mock Invoke-CertToolboxRawHello {
                    $choice = $script:acceptedGroup | Where-Object { $Group -contains $_ } | Select-Object -First 1
                    if ($null -eq $choice) {
                        return [PSCustomObject]@{ ServerHello = $false; Alert = 'handshake_failure'; Error = $null; Stage = $null }
                    }
                    [PSCustomObject]@{ ServerHello = $true; Version = 0x0303; Group = [int]$choice; Error = $null; Stage = $null }
                }

                $result = Find-CertToolboxServerGroup -Connection $script:connectionSettings -Protocol Tls12 -CipherSuite 0xC02F, 0x009C, 0xC013

                ($result.Group -join ',') | Should -Be '23,29'
                $result.ConnectionCount | Should -Be 3
                # 0x009C is a plain RSA suite: offering it would let the server answer without any curve.
                Should -Invoke Invoke-CertToolboxRawHello -Times 3 -Exactly -ParameterFilter { ($CipherSuite -join ',') -eq (0xC02F, 0xC013 -join ',') }
            }

            It 'reports no group, and makes no connection, for a server without ECDHE suites or without any suite' {
                Mock Invoke-CertToolboxRawHello { }

                (Find-CertToolboxServerGroup -Connection $script:connectionSettings -Protocol Tls12 -CipherSuite 0x009C, 0x0035).Group | Should -BeNullOrEmpty
                (Find-CertToolboxServerGroup -Connection $script:connectionSettings -Protocol Tls13 -CipherSuite @()).Group | Should -BeNullOrEmpty
                Should -Invoke Invoke-CertToolboxRawHello -Times 0 -Exactly
            }

            It 'stops trying TLS 1.3 groups when the server can no longer be reached' {
                Mock Invoke-CertToolboxRawHello { [PSCustomObject]@{ ServerHello = $false; Error = 'connection refused'; Stage = 'Connect' } }

                $result = Find-CertToolboxServerGroup -Connection $script:connectionSettings -Protocol Tls13 -CipherSuite 0x1301

                $result.Group | Should -BeNullOrEmpty
                $result.ConnectionCount | Should -Be 1
            }
        }
    }
}

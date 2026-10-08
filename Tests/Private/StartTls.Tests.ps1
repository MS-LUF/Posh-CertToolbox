BeforeDiscovery {
    Import-Module (Join-Path $PSScriptRoot '../../Posh-CertToolbox.psd1') -Force
}

# Everything here runs against a real loopback socket (see Get-TestScriptedConnection): the
# server's side of the dialogue is written in advance, the function under test reads and writes
# the real stream, and what it sent is read back from the server end.
Describe 'Private/StartTls' -Tag Unit {
    InModuleScope 'Posh-CertToolbox' {
        BeforeAll {
            . (Join-Path $PSScriptRoot '../TestHelper.ps1')
        }

        AfterEach {
            if ($script:connection) {
                Close-TestScriptedConnection -Connection $script:connection
                $script:connection = $null
            }
        }

        Describe 'Read-CertToolboxTextLine and Send-CertToolboxTextLine' {
            It 'reads one line at a time and leaves the following bytes on the stream' {
                $script:connection = Get-TestScriptedConnection -ServerLine 'first line', 'second line'

                Read-CertToolboxTextLine -Stream $script:connection.Stream | Should -Be 'first line'
                # Nothing past the line terminator may have been consumed: after a real upgrade
                # the next bytes are the TLS handshake.
                $script:connection.Client.Available | Should -Be ('second line'.Length + 2)
                Read-CertToolboxTextLine -Stream $script:connection.Stream | Should -Be 'second line'
            }

            It 'throws when the server closes the connection before ending the line' {
                $script:connection = Get-TestScriptedConnection
                $script:connection.Server.Close()

                { Read-CertToolboxTextLine -Stream $script:connection.Stream } |
                    Should -Throw -ExceptionType ([System.IO.EndOfStreamException])
            }

            It 'throws on a line longer than the limit' {
                $script:connection = Get-TestScriptedConnection -ServerLine ('x' * 50)

                { Read-CertToolboxTextLine -Stream $script:connection.Stream -MaxLength 10 } | Should -Throw '*longer than 10*'
            }

            It 'fails within the socket timeout when the server stays silent' {
                $script:connection = Get-TestScriptedConnection -TimeoutMs 500
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

                { Read-CertToolboxTextLine -Stream $script:connection.Stream } | Should -Throw

                $stopwatch.ElapsedMilliseconds | Should -BeLessThan 4000
            }

            It 'sends a line terminated by CRLF' {
                $script:connection = Get-TestScriptedConnection

                Send-CertToolboxTextLine -Stream $script:connection.Stream -Line 'EHLO client.example'

                $bytes = New-Object byte[] 64
                Start-Sleep -Milliseconds 100
                $read = $script:connection.Server.GetStream().Read($bytes, 0, $bytes.Length)
                [System.Text.Encoding]::ASCII.GetString($bytes, 0, $read) | Should -Be "EHLO client.example`r`n"
            }
        }

        Describe 'Read-CertToolboxSmtpReply' {
            It 'reads a multi-line reply up to its last line' {
                $script:connection = Get-TestScriptedConnection -ServerLine '250-mail.example', '250-SIZE 1000', '250 STARTTLS', '220 next reply'

                $reply = Read-CertToolboxSmtpReply -Stream $script:connection.Stream

                $reply.Code | Should -Be 250
                ($reply.Line -join '|') | Should -Be '250-mail.example|250-SIZE 1000|250 STARTTLS'
            }

            It 'throws on a line that is not an SMTP reply' {
                $script:connection = Get-TestScriptedConnection -ServerLine 'SSH-2.0-OpenSSH'

                { Read-CertToolboxSmtpReply -Stream $script:connection.Stream } | Should -Throw '*Unexpected reply*SSH-2.0*'
            }
        }

        Describe 'Read-CertToolboxImapResponse' {
            It 'reads untagged lines up to the tagged completion and returns its status' {
                $script:connection = Get-TestScriptedConnection -ServerLine '* CAPABILITY IMAP4rev1 STARTTLS', 'ct1 ok done', '* later'

                $response = Read-CertToolboxImapResponse -Stream $script:connection.Stream -Tag 'ct1'

                $response.Status | Should -Be 'OK'
                @($response.Line).Count | Should -Be 2
            }
        }

        Describe 'Invoke-CertToolboxSmtpStartTls' {
            It 'greets with EHLO, then sends STARTTLS when the server advertises it' {
                $script:connection = Get-TestScriptedConnection -ServerLine @(
                    '220-mail.example ESMTP', '220 ready',
                    '250-mail.example', '250-SIZE 1000', '250-STARTTLS', '250 8BITMIME',
                    '220 2.0.0 Ready to start TLS'
                )

                $dialogue = @(Invoke-CertToolboxSmtpStartTls -Stream $script:connection.Stream -EhloName 'client.example')

                (Get-TestClientOutput -Connection $script:connection) -join '|' | Should -Be 'EHLO client.example|STARTTLS'
                $dialogue[0] | Should -Be 'S: 220-mail.example ESMTP'
                $dialogue | Should -Contain 'C: EHLO client.example'
                $dialogue[-1] | Should -Be 'S: 220 2.0.0 Ready to start TLS'
            }

            It 'announces this machine''s host name by default' {
                $script:connection = Get-TestScriptedConnection -ServerLine '220 ready', '250 STARTTLS', '220 go'

                Invoke-CertToolboxSmtpStartTls -Stream $script:connection.Stream | Out-Null

                (Get-TestClientOutput -Connection $script:connection)[0] | Should -Be "EHLO $([System.Net.Dns]::GetHostName())"
            }

            It 'throws without sending STARTTLS when the server does not advertise it' {
                $script:connection = Get-TestScriptedConnection -ServerLine '220 ready', '250-mail.example', '250 SIZE 1000'

                { Invoke-CertToolboxSmtpStartTls -Stream $script:connection.Stream -EhloName 'client.example' } |
                    Should -Throw '*does not advertise STARTTLS*'
                (Get-TestClientOutput -Connection $script:connection) -join '|' | Should -Be 'EHLO client.example'
            }

            It 'does not mistake another keyword containing the word for the extension' {
                $script:connection = Get-TestScriptedConnection -ServerLine '220 ready', '250-mail.example', '250 X-STARTTLSISH'

                { Invoke-CertToolboxSmtpStartTls -Stream $script:connection.Stream -EhloName 'client.example' } |
                    Should -Throw '*does not advertise STARTTLS*'
            }

            It 'throws with the server''s reply when the greeting is not 220' {
                $script:connection = Get-TestScriptedConnection -ServerLine '554 no service for you'

                { Invoke-CertToolboxSmtpStartTls -Stream $script:connection.Stream -EhloName 'client.example' } |
                    Should -Throw '*did not greet with 220*554 no service for you*'
            }

            It 'throws with the server''s reply when STARTTLS is refused' {
                $script:connection = Get-TestScriptedConnection -ServerLine '220 ready', '250 STARTTLS', '454 TLS not available'

                { Invoke-CertToolboxSmtpStartTls -Stream $script:connection.Stream -EhloName 'client.example' } |
                    Should -Throw '*refused STARTTLS*454 TLS not available*'
            }
        }

        Describe 'Invoke-CertToolboxImapStartTls' {
            It 'queries the capabilities, then sends STARTTLS when the server lists it' {
                $script:connection = Get-TestScriptedConnection -ServerLine @(
                    '* OK IMAP4rev1 server ready',
                    '* CAPABILITY IMAP4rev1 IDLE starttls LOGINDISABLED', 'ct1 OK CAPABILITY completed',
                    'ct2 OK Begin TLS negotiation now'
                )

                $dialogue = @(Invoke-CertToolboxImapStartTls -Stream $script:connection.Stream)

                (Get-TestClientOutput -Connection $script:connection) -join '|' | Should -Be 'ct1 CAPABILITY|ct2 STARTTLS'
                $dialogue[-1] | Should -Be 'S: ct2 OK Begin TLS negotiation now'
            }

            It 'queries the capabilities even when the greeting already lists them' {
                $script:connection = Get-TestScriptedConnection -ServerLine @(
                    '* OK [CAPABILITY IMAP4rev1 STARTTLS] ready',
                    '* CAPABILITY IMAP4rev1 STARTTLS', 'ct1 OK done', 'ct2 OK go'
                )

                Invoke-CertToolboxImapStartTls -Stream $script:connection.Stream | Out-Null

                (Get-TestClientOutput -Connection $script:connection)[0] | Should -Be 'ct1 CAPABILITY'
            }

            It 'throws without sending STARTTLS when the server does not list it' {
                $script:connection = Get-TestScriptedConnection -ServerLine '* OK ready', '* CAPABILITY IMAP4rev1 IDLE', 'ct1 OK done'

                { Invoke-CertToolboxImapStartTls -Stream $script:connection.Stream } | Should -Throw '*does not list STARTTLS*'
                (Get-TestClientOutput -Connection $script:connection) -join '|' | Should -Be 'ct1 CAPABILITY'
            }

            It 'throws on a greeting that is not "* OK"' {
                $script:connection = Get-TestScriptedConnection -ServerLine '* PREAUTH already logged in'

                { Invoke-CertToolboxImapStartTls -Stream $script:connection.Stream } | Should -Throw '*did not greet*PREAUTH*'
            }

            It 'throws with the server''s reply when STARTTLS is refused' {
                $script:connection = Get-TestScriptedConnection -ServerLine '* OK ready', '* CAPABILITY STARTTLS', 'ct1 OK done', 'ct2 BAD not now'

                { Invoke-CertToolboxImapStartTls -Stream $script:connection.Stream } | Should -Throw '*refused STARTTLS*ct2 BAD not now*'
            }
        }

        Describe 'Invoke-CertToolboxPop3StartTls' {
            It 'queries the capabilities, then sends STLS when the server lists it' {
                $script:connection = Get-TestScriptedConnection -ServerLine @(
                    '+OK POP3 server ready', '+OK Capability list follows', 'TOP', 'STLS', 'UIDL', '.', '+OK Begin TLS negotiation'
                )

                $dialogue = @(Invoke-CertToolboxPop3StartTls -Stream $script:connection.Stream)

                (Get-TestClientOutput -Connection $script:connection) -join '|' | Should -Be 'CAPA|STLS'
                $dialogue[-1] | Should -Be 'S: +OK Begin TLS negotiation'
            }

            It 'throws without sending STLS when the server does not list it' {
                $script:connection = Get-TestScriptedConnection -ServerLine '+OK ready', '+OK list follows', 'TOP', 'UIDL', '.'

                { Invoke-CertToolboxPop3StartTls -Stream $script:connection.Stream } | Should -Throw '*does not list STLS*'
                (Get-TestClientOutput -Connection $script:connection) -join '|' | Should -Be 'CAPA'
            }

            It 'tries STLS anyway when the server does not support CAPA' {
                $script:connection = Get-TestScriptedConnection -ServerLine '+OK ready', '-ERR unknown command', '+OK go ahead'

                Invoke-CertToolboxPop3StartTls -Stream $script:connection.Stream | Out-Null

                (Get-TestClientOutput -Connection $script:connection) -join '|' | Should -Be 'CAPA|STLS'
            }

            It 'throws with the server''s reply when the greeting is not +OK or STLS is refused' {
                $script:connection = Get-TestScriptedConnection -ServerLine '-ERR too many connections'
                { Invoke-CertToolboxPop3StartTls -Stream $script:connection.Stream } | Should -Throw '*did not greet*too many connections*'
                Close-TestScriptedConnection -Connection $script:connection

                $script:connection = Get-TestScriptedConnection -ServerLine '+OK ready', '+OK list', 'STLS', '.', '-ERR TLS unavailable'
                { Invoke-CertToolboxPop3StartTls -Stream $script:connection.Stream } | Should -Throw '*refused STLS*TLS unavailable*'
            }
        }

        Describe 'Invoke-CertToolboxStartTls' {
            It 'dispatches to the function of the requested protocol with its options' {
                Mock Invoke-CertToolboxSmtpStartTls { 'S: smtp' }
                Mock Invoke-CertToolboxImapStartTls { 'S: imap' }
                Mock Invoke-CertToolboxPop3StartTls { 'S: pop3' }
                $stream = [System.IO.MemoryStream]::new()

                Invoke-CertToolboxStartTls -StartTls Smtp -Stream $stream -SmtpEhloName 'client.example' | Should -Be 'S: smtp'
                Invoke-CertToolboxStartTls -StartTls Imap -Stream $stream | Should -Be 'S: imap'
                Invoke-CertToolboxStartTls -StartTls Pop3 -Stream $stream | Should -Be 'S: pop3'

                Should -Invoke Invoke-CertToolboxSmtpStartTls -Times 1 -Exactly -ParameterFilter { $EhloName -eq 'client.example' }
                Should -Invoke Invoke-CertToolboxImapStartTls -Times 1 -Exactly
                Should -Invoke Invoke-CertToolboxPop3StartTls -Times 1 -Exactly
            }

            It 'writes the dialogue to the verbose stream up to the point of failure' {
                $script:connection = Get-TestScriptedConnection -ServerLine '220 ready', '250 SIZE 1000'

                # Collected through the pipeline as it is emitted: the call ends by throwing, which
                # would discard anything only assigned from its output.
                $output = [System.Collections.Generic.List[object]]::new()
                {
                    Invoke-CertToolboxStartTls -StartTls Smtp -Stream $script:connection.Stream -SmtpEhloName 'client.example' -Verbose 4>&1 |
                        ForEach-Object { $output.Add($_) }
                } | Should -Throw '*does not advertise STARTTLS*'

                $verbose = @($output | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] } | ForEach-Object { $_.Message })
                $verbose | Should -Contain 'Smtp S: 220 ready'
                $verbose | Should -Contain 'Smtp C: EHLO client.example'
            }
        }

        Describe 'Invoke-CertToolboxTlsProbe with StartTls' {
            It 'runs the plaintext exchange on the connection before the handshake and returns its dialogue' {
                $script:order = [System.Collections.Generic.List[string]]::new()
                $script:connection = Get-TestScriptedConnection
                Mock Connect-CertToolboxTcpClient { $script:connection.Client }
                Mock Invoke-CertToolboxStartTls { $script:order.Add('starttls'); 'S: 220 ready'; 'C: STARTTLS' }
                Mock Invoke-CertToolboxTlsHandshake { $script:order.Add('handshake'); [PSCustomObject]@{ Protocol = 'Tls13' } }

                $result = Invoke-CertToolboxTlsProbe -HostName 'mail.example' -Port 587 -StartTls Smtp -SmtpEhloName 'client.example'

                ($script:order -join ',') | Should -Be 'starttls,handshake'
                ($result.StartTlsDialogue -join '|') | Should -Be 'S: 220 ready|C: STARTTLS'
                Should -Invoke Invoke-CertToolboxStartTls -Times 1 -Exactly -ParameterFilter { $StartTls -eq 'Smtp' -and $SmtpEhloName -eq 'client.example' }
            }

            It 'does no plaintext exchange for direct TLS' {
                $script:connection = Get-TestScriptedConnection
                Mock Connect-CertToolboxTcpClient { $script:connection.Client }
                Mock Invoke-CertToolboxStartTls {}
                Mock Invoke-CertToolboxTlsHandshake { [PSCustomObject]@{ Protocol = 'Tls13' } }

                $result = Invoke-CertToolboxTlsProbe -HostName 'www.example' -Port 443

                $result.StartTlsDialogue | Should -BeNullOrEmpty
                Should -Invoke Invoke-CertToolboxStartTls -Times 0 -Exactly
            }

            It 'throws the upgrade failure without attempting a handshake' {
                $script:connection = Get-TestScriptedConnection
                Mock Connect-CertToolboxTcpClient { $script:connection.Client }
                Mock Invoke-CertToolboxStartTls { throw [System.Net.ProtocolViolationException]::new('The IMAP server does not list STARTTLS in its capabilities.') }
                Mock Invoke-CertToolboxTlsHandshake {}

                { Invoke-CertToolboxTlsProbe -HostName 'mail.example' -Port 143 -StartTls Imap } |
                    Should -Throw -ExceptionType ([System.Net.ProtocolViolationException])
                Should -Invoke Invoke-CertToolboxTlsHandshake -Times 0 -Exactly
            }
        }
    }
}

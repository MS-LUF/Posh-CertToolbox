BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../Posh-CertToolbox.psd1') -Force
    . (Join-Path $PSScriptRoot '../TestHelper.ps1')
    $script:chain = Get-TestCertificateChain
}

Describe 'Get-CertToolboxTlsCertificate' -Tag Unit {
    BeforeEach {
        Mock -ModuleName Posh-CertToolbox Read-CertToolboxConfigFile { [PSCustomObject]@{ version = '1.0' } }
        Mock -ModuleName Posh-CertToolbox Write-CertToolboxLog {}
    }

    Context 'logging' {
        It 'logs the invocation at Debug, a success at Information and a failure at Error' {
            $script:probeResult = Get-TestTlsProbeResult -ServerCertificate $script:chain.Leaf -LocalCertificate $script:chain.Leaf
            Mock -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe { throw [System.TimeoutException]::new('timed out') } -ParameterFilter { $HostName -eq 'down.example' }
            Mock -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe { $script:probeResult } -ParameterFilter { $HostName -eq 'up.example' }

            'down.example', 'up.example' | Get-CertToolboxTlsCertificate -Port 8443 -ErrorAction SilentlyContinue | Out-Null

            Should -Invoke -ModuleName Posh-CertToolbox Write-CertToolboxLog -Times 1 -Exactly -ParameterFilter {
                $Level -eq 'Debug' -and $CmdletName -eq 'Get-CertToolboxTlsCertificate' -and $BoundParameters.ContainsKey('Port')
            }
            Should -Invoke -ModuleName Posh-CertToolbox Write-CertToolboxLog -Times 1 -Exactly -ParameterFilter {
                $Level -eq 'Information' -and $Target -eq 'up.example:8443' -and $Message -like 'Handshake completed*validation passed*'
            }
            Should -Invoke -ModuleName Posh-CertToolbox Write-CertToolboxLog -Times 1 -Exactly -ParameterFilter {
                $Level -eq 'Error' -and $Target -eq 'down.example:8443' -and $Message -like '*TimeoutException*timed out*'
            }
        }
    }

    Context 'a server that sends a complete chain' {
        BeforeEach {
            $script:probeResult = Get-TestTlsProbeResult `
                -ServerCertificate $script:chain.Leaf, $script:chain.Intermediate `
                -LocalCertificate $script:chain.Leaf, $script:chain.Intermediate, $script:chain.Root
            Mock -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe { $script:probeResult }
        }

        It 'returns the session, the leaf and both chains' {
            $result = Get-CertToolboxTlsCertificate -HostName 'test.example'

            $result.PSObject.TypeNames[0] | Should -Be 'CertToolbox.TlsCertificate'
            $result.HostName | Should -Be 'test.example'
            $result.Port | Should -Be 443
            $result.TargetHost | Should -Be 'test.example'
            $result.RemoteAddress | Should -Be '192.0.2.10'
            $result.Protocol | Should -Be 'Tls13'
            $result.CipherSuite | Should -Be 'TLS_AES_256_GCM_SHA384'
            $result.ValidationPassed | Should -BeTrue
            $result.PolicyError | Should -BeNullOrEmpty
            $result.Certificate.Thumbprint | Should -Be $script:chain.Leaf.Thumbprint
            @($result.ServerChain).Count | Should -Be 2
            @($result.LocalChain).Count | Should -Be 3
            $result.LocalChain[2].Thumbprint | Should -Be $script:chain.Root.Thumbprint
            $result.LocalChain[0].PSObject.Properties['Status'] | Should -Not -BeNullOrEmpty
            $result.MissingIntermediate | Should -BeNullOrEmpty
            $result.ServerSentRoot | Should -BeFalse
            $result.UnusedServerCertificate | Should -BeNullOrEmpty
        }

        It 'lets the operating system choose the protocol by default and uses the host name as target host' {
            Get-CertToolboxTlsCertificate -HostName 'test.example' | Out-Null

            Should -Invoke -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe -Times 1 -Exactly -ParameterFilter {
                $HostName -eq 'test.example' -and $Port -eq 443 -and $TargetHost -eq 'test.example' -and
                [int]$SslProtocol -eq 0 -and $TimeoutMs -eq 10000 -and -not $CheckRevocation
            }
        }

        It 'passes port, target host, combined protocols, timeout and revocation through' {
            Get-CertToolboxTlsCertificate -HostName '192.0.2.10' -Port 8443 -TargetHost 'test.example' `
                -Protocol Tls12, Tls13 -TimeoutSec 3 -CheckRevocation | Out-Null

            $expected = [int]([System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls13)
            Should -Invoke -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe -Times 1 -Exactly -ParameterFilter {
                $HostName -eq '192.0.2.10' -and $Port -eq 8443 -and $TargetHost -eq 'test.example' -and
                [int]$SslProtocol -eq $expected -and $TimeoutMs -eq 3000 -and $CheckRevocation
            }
        }

        It 'accepts host names from the pipeline, as strings and by property name' {
            $fromStrings = 'a.example', 'b.example' | Get-CertToolboxTlsCertificate
            @($fromStrings).Count | Should -Be 2

            $fromObject = [PSCustomObject]@{ HostName = 'c.example'; Port = 9443 } | Get-CertToolboxTlsCertificate
            $fromObject.Port | Should -Be 9443
        }
    }

    Context 'StartTls' {
        BeforeEach {
            $script:probeResult = Get-TestTlsProbeResult -ServerCertificate $script:chain.Leaf -LocalCertificate $script:chain.Leaf `
                -StartTlsDialogue 'S: 220 ready', 'C: STARTTLS', 'S: 220 go'
            Mock -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe { $script:probeResult }
        }

        It 'does not pass StartTls to the probe and reports none for direct TLS' {
            $result = Get-CertToolboxTlsCertificate -HostName 'test.example'

            $result.StartTls | Should -BeNullOrEmpty
            Should -Invoke -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe -Times 1 -Exactly -ParameterFilter { -not $StartTls }
        }

        It 'uses the standard port of the protocol when no port is given' -ForEach @(
            @{ Name = 'Smtp'; ExpectedPort = 25 }
            @{ Name = 'Imap'; ExpectedPort = 143 }
            @{ Name = 'Pop3'; ExpectedPort = 110 }
        ) {
            $result = Get-CertToolboxTlsCertificate -HostName 'mail.example' -StartTls $Name

            $result.Port | Should -Be $ExpectedPort
            $result.StartTls | Should -Be $Name
            Should -Invoke -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe -Times 1 -Exactly -ParameterFilter {
                $StartTls -eq $Name -and $Port -eq $ExpectedPort
            }
        }

        It 'keeps an explicit port and passes the EHLO name through' {
            $result = Get-CertToolboxTlsCertificate -HostName 'mail.example' -Port 587 -StartTls Smtp -SmtpEhloName 'client.example'

            $result.Port | Should -Be 587
            Should -Invoke -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe -Times 1 -Exactly -ParameterFilter {
                $StartTls -eq 'Smtp' -and $Port -eq 587 -and $SmtpEhloName -eq 'client.example'
            }
        }

        It 'takes StartTls per object from the pipeline without leaking the port to the next object' {
            $results = @(
                [PSCustomObject]@{ HostName = 'mail.example'; StartTls = 'Imap' }
                [PSCustomObject]@{ HostName = 'www.example' }
            ) | Get-CertToolboxTlsCertificate

            $results[0].Port | Should -Be 143
            $results[0].StartTls | Should -Be 'Imap'
            $results[1].Port | Should -Be 443
            $results[1].StartTls | Should -BeNullOrEmpty
        }

        It 'rejects an EHLO name that could inject another command' {
            { Get-CertToolboxTlsCertificate -HostName 'mail.example' -StartTls Smtp -SmtpEhloName "a`r`nQUIT" } | Should -Throw
        }

        It 'logs the plaintext dialogue at Debug level' {
            Get-CertToolboxTlsCertificate -HostName 'mail.example' -StartTls Smtp | Out-Null

            Should -Invoke -ModuleName Posh-CertToolbox Write-CertToolboxLog -Times 1 -Exactly -ParameterFilter {
                $Level -eq 'Debug' -and $Target -eq 'mail.example:25' -and $Message -like 'Smtp dialogue before TLS: S: 220 ready | C: STARTTLS | S: 220 go'
            }
        }
    }

    Context 'chain problems' {
        It 'reports an intermediate the server did not send' {
            $script:probeResult = Get-TestTlsProbeResult -ServerCertificate $script:chain.Leaf `
                -LocalCertificate $script:chain.Leaf, $script:chain.Intermediate, $script:chain.Root
            Mock -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe { $script:probeResult }

            $result = Get-CertToolboxTlsCertificate -HostName 'test.example'

            @($result.MissingIntermediate).Count | Should -Be 1
            $result.MissingIntermediate[0].Subject | Should -Be 'CN=CertToolbox Test Intermediate'
        }

        It 'reports a root sent by the server and an unused server certificate' {
            $script:probeResult = Get-TestTlsProbeResult `
                -ServerCertificate $script:chain.Leaf, $script:chain.Intermediate, $script:chain.Root, $script:chain.Other `
                -LocalCertificate $script:chain.Leaf, $script:chain.Intermediate, $script:chain.Root
            Mock -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe { $script:probeResult }

            $result = Get-CertToolboxTlsCertificate -HostName 'test.example'

            $result.ServerSentRoot | Should -BeTrue
            @($result.UnusedServerCertificate).Count | Should -Be 1
            $result.UnusedServerCertificate[0].Subject | Should -Be 'CN=Unrelated Self Signed'
        }

        It 'reports validation failures without failing the call' {
            $script:probeResult = Get-TestTlsProbeResult -ServerCertificate $script:chain.Other -LocalCertificate $script:chain.Other `
                -PolicyErrors 'RemoteCertificateNameMismatch, RemoteCertificateChainErrors' -ChainStatus 'UntrustedRoot'
            Mock -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe { $script:probeResult }

            $result = Get-CertToolboxTlsCertificate -HostName 'test.example'

            $result.ValidationPassed | Should -BeFalse
            ($result.PolicyError -join ',') | Should -Be 'RemoteCertificateNameMismatch,RemoteCertificateChainErrors'
            ($result.ChainStatus -join ',') | Should -Be 'UntrustedRoot'
        }
    }

    Context 'connection failure' {
        It 'writes a non-terminating error for the failing host and still processes the others' {
            $script:probeResult = Get-TestTlsProbeResult -ServerCertificate $script:chain.Leaf -LocalCertificate $script:chain.Leaf
            Mock -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe { throw [System.TimeoutException]::new('timed out') } -ParameterFilter { $HostName -eq 'down.example' }
            Mock -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe { $script:probeResult } -ParameterFilter { $HostName -eq 'up.example' }

            $output = 'down.example', 'up.example' | Get-CertToolboxTlsCertificate 2>&1

            $errors = @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
            $results = @($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] })
            $errors.Count | Should -Be 1
            $errors[0].FullyQualifiedErrorId | Should -BeLike 'TlsConnectionFailed*'
            $errors[0].TargetObject | Should -Be 'down.example:443'
            $errors[0].Exception | Should -BeOfType ([System.TimeoutException])
            $results.Count | Should -Be 1
            $results[0].HostName | Should -Be 'up.example'
        }
    }
}

# Real endpoints: this is what checks the hand-written handshake and chain capture against
# actual servers, on whichever runtime and platform the tests run.
Describe 'Get-CertToolboxTlsCertificate against real endpoints' -Tag Integration {
    It 'gets a valid chain whose first server certificate is the leaf' {
        $result = Get-CertToolboxTlsCertificate -HostName 'www.google.com'

        $result.ValidationPassed | Should -BeTrue
        $result.Certificate.SubjectAlternativeName | Should -Contain 'www.google.com'
        @($result.ServerChain).Count | Should -BeGreaterThan 1
        $result.ServerChain[0].Thumbprint | Should -Be $result.Certificate.Thumbprint
        $result.LocalChain[0].Thumbprint | Should -Be $result.Certificate.Thumbprint
        @($result.ServerChain | Group-Object Thumbprint | Where-Object Count -gt 1) | Should -BeNullOrEmpty
    }

    It 'shows that a server sending only its leaf is missing intermediates' {
        $result = Get-CertToolboxTlsCertificate -HostName 'incomplete-chain.badssl.com'

        @($result.ServerChain).Count | Should -Be 1
        # Whether the local chain can be completed depends on the machine (cached or downloaded
        # intermediates); when it is, the completed part must show up as missing from the server.
        if (@($result.LocalChain).Count -gt 1) {
            @($result.MissingIntermediate).Count | Should -BeGreaterThan 0
        } else {
            $result.ValidationPassed | Should -BeFalse
        }
    }

    It 'reports an expired certificate instead of failing' {
        $result = Get-CertToolboxTlsCertificate -HostName 'expired.badssl.com'

        $result.ValidationPassed | Should -BeFalse
        $result.PolicyError | Should -Contain 'RemoteCertificateChainErrors'
        $result.Certificate.DaysUntilExpiry | Should -BeLessThan 0
    }

    # Public mail servers: these also confirm the plaintext exchange against real implementations.
    It 'gets the certificate of a mail server after <StartTls> STARTTLS on port <Port>' -ForEach @(
        @{ HostName = 'smtp.gmail.com'; Port = 587; StartTls = 'Smtp' }
        @{ HostName = 'outlook.office365.com'; Port = 143; StartTls = 'Imap' }
        @{ HostName = 'outlook.office365.com'; Port = 110; StartTls = 'Pop3' }
    ) {
        $result = Get-CertToolboxTlsCertificate -HostName $HostName -Port $Port -StartTls $StartTls

        $result.StartTls | Should -Be $StartTls
        $result.ValidationPassed | Should -BeTrue
        $result.ServerChain[0].Thumbprint | Should -Be $result.Certificate.Thumbprint
        @($result.LocalChain).Count | Should -BeGreaterThan 1
    }

    It 'reports a server that does not offer the upgrade as an error, not as a TLS failure' {
        # An HTTPS port answers an SMTP client with nothing it can read as a greeting.
        $output = @(Get-CertToolboxTlsCertificate -HostName 'www.google.com' -Port 80 -StartTls Smtp -TimeoutSec 3 2>&1)

        $errors = @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
        $errors.Count | Should -Be 1
        $errors[0].FullyQualifiedErrorId | Should -BeLike 'TlsConnectionFailed*'
    }

    It 'reports a name mismatch' {
        (Get-CertToolboxTlsCertificate -HostName 'wrong.host.badssl.com').PolicyError | Should -Contain 'RemoteCertificateNameMismatch'
    }
}

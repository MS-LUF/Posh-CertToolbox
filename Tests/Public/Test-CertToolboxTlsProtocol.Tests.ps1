BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../Posh-CertToolbox.psd1') -Force
    . (Join-Path $PSScriptRoot '../TestHelper.ps1')
    $script:chain = Get-TestCertificateChain
}

Describe 'Test-CertToolboxTlsProtocol' -Tag Unit {
    BeforeEach {
        Mock -ModuleName Posh-CertToolbox Read-CertToolboxConfigFile { [PSCustomObject]@{ version = '1.0' } }
        Mock -ModuleName Posh-CertToolbox Write-CertToolboxLog {}

        $script:tls12Result = Get-TestTlsProbeResult -ServerCertificate $script:chain.Leaf -LocalCertificate $script:chain.Leaf -Protocol 'Tls12'
        Mock -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe {
            throw [System.Exception]::new('wrapper', [System.ComponentModel.Win32Exception]::new('no common algorithm'))
        }
        Mock -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe { $script:tls12Result } -ParameterFilter {
            $SslProtocol -eq [System.Security.Authentication.SslProtocols]::Tls12
        }
    }

    It 'probes every protocol version by default, one connection each, oldest first' {
        $results = @(Test-CertToolboxTlsProtocol -HostName 'test.example')

        ($results.Protocol -join ',') | Should -Be 'Ssl3,Tls,Tls11,Tls12,Tls13'
        $results[0].PSObject.TypeNames[0] | Should -Be 'CertToolbox.TlsProtocolResult'
        Should -Invoke -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe -Times 5 -Exactly
    }

    It 'reports a negotiated version with its session details and no error' {
        $result = Test-CertToolboxTlsProtocol -HostName 'test.example' -Protocol Tls12

        $result.Negotiated | Should -BeTrue
        $result.NegotiatedProtocol | Should -Be 'Tls12'
        $result.CipherSuite | Should -Be 'TLS_AES_256_GCM_SHA384'
        $result.ErrorType | Should -BeNullOrEmpty
        $result.ErrorMessage | Should -BeNullOrEmpty
    }

    It 'reports a version that could not be negotiated with the innermost error, without failing' {
        # The error stream is checked with 2>&1, not -ErrorVariable: that variable also collects
        # errors caught and handled inside the cmdlet.
        $output = @(Test-CertToolboxTlsProtocol -HostName 'test.example' -Protocol Tls11 2>&1)

        @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) | Should -BeNullOrEmpty
        $result = $output[0]
        $result.Negotiated | Should -BeFalse
        $result.NegotiatedProtocol | Should -BeNullOrEmpty
        $result.ErrorType | Should -Be 'Win32Exception'
        $result.ErrorMessage | Should -Be 'no common algorithm'
    }

    It 'probes only the requested versions and passes port, target host and timeout through' {
        $results = @(Test-CertToolboxTlsProtocol -HostName '192.0.2.10' -Port 993 -TargetHost 'mail.example' -Protocol Tls12, Tls13 -TimeoutSec 4)

        ($results.Protocol -join ',') | Should -Be 'Tls12,Tls13'
        $results[0].TargetHost | Should -Be 'mail.example'
        Should -Invoke -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe -Times 2 -Exactly -ParameterFilter {
            $HostName -eq '192.0.2.10' -and $Port -eq 993 -and $TargetHost -eq 'mail.example' -and $TimeoutMs -eq 4000
        }
    }

    It 'logs the invocation at Debug and every probe result at Information, negotiated or not' {
        Test-CertToolboxTlsProtocol -HostName 'test.example' -Protocol Tls11, Tls12 | Out-Null

        Should -Invoke -ModuleName Posh-CertToolbox Write-CertToolboxLog -Times 1 -Exactly -ParameterFilter { $Level -eq 'Debug' }
        Should -Invoke -ModuleName Posh-CertToolbox Write-CertToolboxLog -Times 1 -Exactly -ParameterFilter {
            $Level -eq 'Information' -and $Target -eq 'test.example:443' -and $Message -like 'Tls12: negotiated*'
        }
        Should -Invoke -ModuleName Posh-CertToolbox Write-CertToolboxLog -Times 1 -Exactly -ParameterFilter {
            $Level -eq 'Information' -and $Message -like 'Tls11: not negotiated (Win32Exception: no common algorithm)'
        }
        Should -Invoke -ModuleName Posh-CertToolbox Write-CertToolboxLog -Times 0 -Exactly -ParameterFilter { $Level -eq 'Error' }
    }

    It 'passes StartTls on every probe, defaults to the protocol port and reports it' {
        $results = @(Test-CertToolboxTlsProtocol -HostName 'mail.example' -StartTls Imap -Protocol Tls12, Tls13)

        ($results.Port -join ',') | Should -Be '143,143'
        ($results.StartTls -join ',') | Should -Be 'Imap,Imap'
        Should -Invoke -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe -Times 2 -Exactly -ParameterFilter {
            $StartTls -eq 'Imap' -and $Port -eq 143
        }
    }

    It 'keeps an explicit port and passes the EHLO name through' {
        Test-CertToolboxTlsProtocol -HostName 'mail.example' -Port 587 -StartTls Smtp -SmtpEhloName 'client.example' -Protocol Tls12 | Out-Null

        Should -Invoke -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe -Times 1 -Exactly -ParameterFilter {
            $StartTls -eq 'Smtp' -and $Port -eq 587 -and $SmtpEhloName -eq 'client.example'
        }
    }

    It 'does not pass StartTls for direct TLS' {
        $result = Test-CertToolboxTlsProtocol -HostName 'test.example' -Protocol Tls12

        $result.StartTls | Should -BeNullOrEmpty
        Should -Invoke -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe -Times 1 -Exactly -ParameterFilter { -not $StartTls }
    }

    It 'accepts several hosts from the pipeline' {
        $results = @('a.example', 'b.example' | Test-CertToolboxTlsProtocol -Protocol Tls12)

        ($results.HostName -join ',') | Should -Be 'a.example,b.example'
    }
}

Describe 'Test-CertToolboxTlsProtocol against real endpoints' -Tag Integration {
    It 'probes a mail server through SMTP STARTTLS on each connection' {
        $results = @(Test-CertToolboxTlsProtocol -HostName 'smtp.gmail.com' -Port 587 -StartTls Smtp -Protocol Tls12, Tls13)

        ($results.StartTls -join ',') | Should -Be 'Smtp,Smtp'
        @($results | Where-Object Negotiated).Count | Should -BeGreaterThan 0
    }

    It 'negotiates only TLS 1.2 with a server that accepts nothing else' {
        $results = @(Test-CertToolboxTlsProtocol -HostName 'tls-v1-2.badssl.com' -Port 1012)

        ($results | Where-Object Protocol -eq 'Tls12').Negotiated | Should -BeTrue
        @($results | Where-Object { $_.Protocol -ne 'Tls12' -and $_.Negotiated }) | Should -BeNullOrEmpty
        @($results | Where-Object { -not $_.Negotiated -and -not $_.ErrorMessage }) | Should -BeNullOrEmpty
    }
}

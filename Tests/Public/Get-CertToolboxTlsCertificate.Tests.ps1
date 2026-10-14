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

    Context 'TestCertificateUrl' {
        BeforeEach {
            $script:probeResult = Get-TestTlsProbeResult `
                -ServerCertificate $script:chain.Leaf `
                -LocalCertificate $script:chain.Leaf, $script:chain.Intermediate, $script:chain.Root
            Mock -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe { $script:probeResult }

            $script:urlRows = @(
                [PSCustomObject]@{ Type = 'Crl'; Url = 'http://crl.test.example/ca.crl'; Result = 'NotRevoked' }
                [PSCustomObject]@{ Type = 'Ocsp'; Url = 'http://ocsp.test.example/'; Result = 'Revoked' }
                [PSCustomObject]@{ Type = 'CaIssuers'; Url = 'ldap://directory.test.example/'; Result = 'Skipped' }
            )
            Mock -ModuleName Posh-CertToolbox Invoke-CertToolboxCertificateUrlTest { $script:urlRows }
        }

        It 'does not test any URL and leaves UrlTest empty by default' {
            $result = Get-CertToolboxTlsCertificate -HostName 'test.example'

            $result.PSObject.Properties['UrlTest'] | Should -Not -BeNullOrEmpty
            $result.UrlTest | Should -BeNullOrEmpty
            Should -Invoke -ModuleName Posh-CertToolbox Invoke-CertToolboxCertificateUrlTest -Times 0 -Exactly
        }

        It 'tests both chains with the cmdlet timeout and returns the rows' {
            $result = Get-CertToolboxTlsCertificate -HostName 'test.example' -TestCertificateUrl -TimeoutSec 4

            @($result.UrlTest).Count | Should -Be 3
            ($result.UrlTest.Result -join ',') | Should -Be 'NotRevoked,Revoked,Skipped'
            Should -Invoke -ModuleName Posh-CertToolbox Invoke-CertToolboxCertificateUrlTest -Times 1 -Exactly -ParameterFilter {
                $ServerCertificate.Count -eq 1 -and $LocalCertificate.Count -eq 3 -and $TimeoutSec -eq 4 -and
                $ServerCertificate[0].Thumbprint -eq $script:chain.Leaf.Thumbprint
            }
        }

        It 'returns an empty list, not nothing, when the tests ran but found no URL' {
            Mock -ModuleName Posh-CertToolbox Invoke-CertToolboxCertificateUrlTest { }

            $result = Get-CertToolboxTlsCertificate -HostName 'test.example' -TestCertificateUrl

            , $result.UrlTest | Should -BeOfType [array]
            @($result.UrlTest).Count | Should -Be 0
        }

        It 'logs a summary naming the URLs with a problem, and only those' {
            Get-CertToolboxTlsCertificate -HostName 'test.example' -TestCertificateUrl | Out-Null

            Should -Invoke -ModuleName Posh-CertToolbox Write-CertToolboxLog -Times 1 -Exactly -ParameterFilter {
                $Level -eq 'Information' -and $Target -eq 'test.example:443' -and
                $Message -eq 'Certificate URL tests: 3 run, 1 with a problem: Ocsp http://ocsp.test.example/ -> Revoked.'
            }
        }
    }

    Context 'EveryAddress' {
        BeforeEach {
            $script:probeResult = Get-TestTlsProbeResult -ServerCertificate $script:chain.Leaf -LocalCertificate $script:chain.Leaf
            Mock -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe { $script:probeResult }
            Mock -ModuleName Posh-CertToolbox Resolve-CertToolboxHostAddress {
                [System.Net.IPAddress]::Parse('192.0.2.10')
                [System.Net.IPAddress]::Parse('192.0.2.11')
                [System.Net.IPAddress]::Parse('2001:db8::1')
            }
        }

        It 'does not resolve the name, and names no address to the probe, by default' {
            Get-CertToolboxTlsCertificate -HostName 'many.test.example' | Out-Null

            Should -Invoke -ModuleName Posh-CertToolbox Resolve-CertToolboxHostAddress -Times 0 -Exactly
            Should -Invoke -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe -Times 1 -Exactly -ParameterFilter { $null -eq $Address -and -not $AddressFamily }
        }

        It 'probes each address of the name, keeping the name as host name and server name' {
            $results = @(Get-CertToolboxTlsCertificate -HostName 'many.test.example' -EveryAddress)

            $results.Count | Should -Be 3
            @($results | Where-Object { $_.HostName -ne 'many.test.example' -or $_.TargetHost -ne 'many.test.example' }) | Should -BeNullOrEmpty
            foreach ($expected in '192.0.2.10', '192.0.2.11', '2001:db8::1') {
                Should -Invoke -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe -Times 1 -Exactly -ParameterFilter {
                    "$Address" -eq $expected -and $HostName -eq 'many.test.example' -and $TargetHost -eq 'many.test.example'
                }
            }
        }

        It 'passes the address family to the resolution, and to the probe when not probing every address' {
            Get-CertToolboxTlsCertificate -HostName 'many.test.example' -EveryAddress -AddressFamily IPv4 | Out-Null
            Should -Invoke -ModuleName Posh-CertToolbox Resolve-CertToolboxHostAddress -Times 1 -Exactly -ParameterFilter { $AddressFamily -eq 'IPv4' }

            Get-CertToolboxTlsCertificate -HostName 'many.test.example' -AddressFamily IPv6 | Out-Null
            Should -Invoke -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe -Times 1 -Exactly -ParameterFilter { $null -eq $Address -and $AddressFamily -eq 'IPv6' }
        }

        It 'reports an address that fails as an error naming it, and returns the others' {
            Mock -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe { throw [System.TimeoutException]::new('timed out') } -ParameterFilter { "$Address" -eq '192.0.2.11' }

            $output = Get-CertToolboxTlsCertificate -HostName 'many.test.example' -EveryAddress 2>&1

            $errors = @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
            $results = @($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] })
            $errors.Count | Should -Be 1
            $errors[0].TargetObject | Should -Be 'many.test.example [192.0.2.11]:443'
            $results.Count | Should -Be 2
            Should -Invoke -ModuleName Posh-CertToolbox Write-CertToolboxLog -Times 1 -Exactly -ParameterFilter {
                $Level -eq 'Error' -and $Target -eq 'many.test.example [192.0.2.11]:443'
            }
        }

        It 'reports a name that does not resolve as an error, and carries on with the next name' {
            Mock -ModuleName Posh-CertToolbox Resolve-CertToolboxHostAddress {
                throw [System.InvalidOperationException]::new("'gone.test.example' has no IPv6 address.")
            } -ParameterFilter { $HostName -eq 'gone.test.example' }

            $output = 'gone.test.example', 'many.test.example' | Get-CertToolboxTlsCertificate -EveryAddress 2>&1

            $errors = @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
            $errors.Count | Should -Be 1
            $errors[0].TargetObject | Should -Be 'gone.test.example:443'
            $errors[0].Exception.Message | Should -BeLike '*has no IPv6 address*'
            @($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }).Count | Should -Be 3
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

    # Real CA infrastructure: checks the hand-written CRL and OCSP code against real answers.
    It 'gets Good from a real OCSP responder and reads real CRLs and issuer certificates' {
        $result = Get-CertToolboxTlsCertificate -HostName 'www.microsoft.com' -TestCertificateUrl

        $rows = @($result.UrlTest)
        @($rows | Where-Object { $_.Type -eq 'Ocsp' -and $_.Result -eq 'Good' }).Count | Should -BeGreaterThan 0
        @($rows | Where-Object { $_.Type -eq 'Crl' -and $_.Result -eq 'NotRevoked' -and $_.NextUpdate -gt [datetime]::UtcNow }).Count | Should -BeGreaterThan 0
        @($rows | Where-Object { $_.Type -eq 'CaIssuers' -and $_.Result -eq 'IssuerMatch' }).Count | Should -BeGreaterThan 0
        @($rows | Where-Object { $_.Subject -eq $result.Certificate.Subject -and $_.Result -in 'Revoked', 'Failed' }) | Should -BeNullOrEmpty

        # Real signatures: CRLs, and OCSP answers signed by a delegated responder.
        @($rows | Where-Object { $_.Type -eq 'Ocsp' -and $_.Signature -eq 'Valid' }).Count | Should -BeGreaterThan 0
        @($rows | Where-Object { $_.Type -eq 'Crl' -and $_.Signature -eq 'Valid' }).Count | Should -BeGreaterThan 0
        @($rows | Where-Object { $_.Signature -eq 'Invalid' }) | Should -BeNullOrEmpty
    }

    It 'verifies the real CRLs of another CA, and explains the ones it cannot verify' {
        # Which chain a server sends, and which one the machine builds, depend on the client
        # and on its trust store: a cross-signed certificate at the top of the server's chain
        # has an issuer that is in neither chain, and its CRL is then legitimately NotVerified.
        # So: at least one CRL verifies, none is invalid, and any other says why.
        $rows = @((Get-CertToolboxTlsCertificate -HostName 'www.google.com' -TestCertificateUrl).UrlTest | Where-Object Type -eq 'Crl')

        @($rows | Where-Object Signature -eq 'Valid').Count | Should -BeGreaterThan 0
        @($rows | Where-Object Signature -eq 'Invalid') | Should -BeNullOrEmpty
        @($rows | Where-Object { $_.Signature -eq 'NotVerified' -and $_.Detail -notlike '*issuer certificate is not available*' }) | Should -BeNullOrEmpty
    }

    It 'finds a revoked certificate in its real CRL' {
        $result = Get-CertToolboxTlsCertificate -HostName 'revoked.badssl.com' -TestCertificateUrl

        $leafCrl = @($result.UrlTest | Where-Object { $_.Type -eq 'Crl' -and $_.Thumbprint -eq $result.Certificate.Thumbprint })
        $leafCrl.Count | Should -BeGreaterThan 0
        $leafCrl[0].Result | Should -Be 'Revoked'
    }

    It 'tests the certificates only the local chain has, when the server sent just its leaf' {
        $result = Get-CertToolboxTlsCertificate -HostName 'incomplete-chain.badssl.com' -TestCertificateUrl

        if (@($result.LocalChain).Count -gt 1) {
            @($result.UrlTest | Where-Object Chain -eq 'Local').Count | Should -BeGreaterThan 0
        }
        @($result.UrlTest | Where-Object Chain -eq 'Both').Count | Should -BeGreaterThan 0
    }

    It 'returns one result per address of a name, each from the address it names' {
        $results = @(Get-CertToolboxTlsCertificate -HostName 'www.cloudflare.com' -EveryAddress -AddressFamily IPv4 -TimeoutSec 8)

        # The resolver may hand out a different set between two calls, so only the shape is firm.
        $results.Count | Should -BeGreaterThan 0
        @($results | Where-Object { $_.HostName -ne 'www.cloudflare.com' }) | Should -BeNullOrEmpty
        @($results.RemoteAddress | Where-Object { $_ -match ':' }) | Should -BeNullOrEmpty
        @($results.RemoteAddress | Select-Object -Unique).Count | Should -Be $results.Count
        @($results | Where-Object { -not $_.ValidationPassed }) | Should -BeNullOrEmpty
    }

    It 'reports a name mismatch' {
        (Get-CertToolboxTlsCertificate -HostName 'wrong.host.badssl.com').PolicyError | Should -Contain 'RemoteCertificateNameMismatch'
    }
}

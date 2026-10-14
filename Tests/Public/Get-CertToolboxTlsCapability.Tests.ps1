BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../Posh-CertToolbox.psd1') -Force
    . (Join-Path $PSScriptRoot '../TestHelper.ps1')
    $script:chain = Get-TestCertificateChain

    # What Find-CertToolboxServerCipherSuite returns for one version of a model server.
    function Get-TestSuiteScan {
        param(
            [string] $Protocol,
            [int[]] $CipherSuite = @(),
            [string] $Reason,
            [object] $ServerCipherOrder = $null,
            [switch] $ConnectFailed,
            [switch] $Incomplete,
            [switch] $Stapled
        )

        $first = $null
        if ($CipherSuite.Count -gt 0) {
            $first = [PSCustomObject]@{
                RemoteAddress        = '192.0.2.10'
                SecureRenegotiation  = $true
                ExtendedMasterSecret = $false
                OcspStapled          = [bool]$Stapled
                Complete             = -not $Incomplete
                Certificate          = @($script:chain.Leaf, $script:chain.Intermediate)
            }
        }
        [PSCustomObject]@{
            Protocol          = $Protocol
            Accepted          = ($CipherSuite.Count -gt 0)
            Reason            = $Reason
            CipherSuite       = $CipherSuite
            ServerCipherOrder = $ServerCipherOrder
            FirstAnswer       = $first
            ConnectFailed     = [bool]$ConnectFailed
            ConnectionCount   = $CipherSuite.Count + 1
        }
    }
}

Describe 'Get-CertToolboxTlsCapability' -Tag Unit {
    BeforeEach {
        Mock -ModuleName Posh-CertToolbox Read-CertToolboxConfigFile { [PSCustomObject]@{ version = '1.0' } }
        Mock -ModuleName Posh-CertToolbox Write-CertToolboxLog {}

        # A model server: TLS 1.2 with three suites, one of them weak, and TLS 1.3 with two.
        Mock -ModuleName Posh-CertToolbox Find-CertToolboxServerCipherSuite {
            switch ($Protocol) {
                'Tls12' { Get-TestSuiteScan -Protocol Tls12 -CipherSuite 0xC030, 0xC013, 0x0005 -ServerCipherOrder $true -Stapled }
                'Tls13' { Get-TestSuiteScan -Protocol Tls13 -CipherSuite 0x1302, 0x1301 -ServerCipherOrder $false }
                default { Get-TestSuiteScan -Protocol $Protocol -Reason "The server refused with the alert 'protocol_version'." }
            }
        }
        Mock -ModuleName Posh-CertToolbox Find-CertToolboxServerGroup {
            if ($Protocol -eq 'Tls13') {
                return [PSCustomObject]@{ Group = [int[]](29, 4588); ConnectionCount = 11 }
            }
            [PSCustomObject]@{ Group = [int[]](23, 999); ConnectionCount = 3 }
        }
    }

    It 'reports each version probed, oldest first, with why a version is not accepted' {
        $result = Get-CertToolboxTlsCapability -HostName 'server.test.example'

        $result.PSObject.TypeNames[0] | Should -Be 'CertToolbox.TlsCapability'
        $result.HostName | Should -Be 'server.test.example'
        $result.Port | Should -Be 443
        $result.TargetHost | Should -Be 'server.test.example'
        $result.RemoteAddress | Should -Be '192.0.2.10'
        ($result.Protocol.Protocol -join ',') | Should -Be 'Ssl3,Tls,Tls11,Tls12,Tls13'
        ($result.Protocol.Accepted -join ',') | Should -Be 'False,False,False,True,True'
        ($result.Protocol.CipherSuiteCount -join ',') | Should -Be '0,0,0,3,2'
        $result.Protocol[0].Reason | Should -BeLike '*protocol_version*'
        $result.Protocol[3].ServerCipherOrder | Should -BeTrue
        $result.Protocol[4].ServerCipherOrder | Should -BeFalse
        $result.Protocol[3].Reason | Should -BeNullOrEmpty
    }

    It 'lists the cipher suites per version in the server''s order, with their facts' {
        $result = Get-CertToolboxTlsCapability -HostName 'server.test.example'

        @($result.CipherSuite).Count | Should -Be 5
        $tls12 = @($result.CipherSuite | Where-Object Protocol -eq 'Tls12')
        ($tls12.Order -join ',') | Should -Be '1,2,3'
        ($tls12.Name -join ',') | Should -Be 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_RC4_128_SHA'
        $tls12[0].Code | Should -Be '0xC030'
        ($tls12.ForwardSecrecy -join ',') | Should -Be 'True,True,False'
        ($tls12.AuthenticatedEncryption -join ',') | Should -Be 'True,False,False'
        ($tls12.Weak -join ',') | Should -Be 'False,False,True'
        (@($result.CipherSuite | Where-Object Protocol -eq 'Tls13').Name -join ',') | Should -Be 'TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256'
    }

    It 'looks for groups on TLS 1.3 and on the highest earlier version accepted, and names them' {
        $result = Get-CertToolboxTlsCapability -HostName 'server.test.example'

        ($result.Group | ForEach-Object { "$($_.Protocol):$($_.Name):$($_.Code)" }) -join ',' |
            Should -Be 'Tls12:secp256r1:23,Tls12:group_999:999,Tls13:x25519:29,Tls13:X25519MLKEM768:4588'
        Should -Invoke -ModuleName Posh-CertToolbox Find-CertToolboxServerGroup -Times 1 -Exactly -ParameterFilter {
            $Protocol -eq 'Tls12' -and ($CipherSuite -join ',') -eq (0xC030, 0xC013, 0x0005 -join ',')
        }
        Should -Invoke -ModuleName Posh-CertToolbox Find-CertToolboxServerGroup -Times 1 -Exactly -ParameterFilter { $Protocol -eq 'Tls13' }
        Should -Invoke -ModuleName Posh-CertToolbox Find-CertToolboxServerGroup -Times 2 -Exactly
    }

    It 'takes the handshake features and the chain as sent from the earlier version' {
        $result = Get-CertToolboxTlsCapability -HostName 'server.test.example'

        $result.OcspStapling | Should -BeTrue
        $result.SecureRenegotiation | Should -BeTrue
        $result.ExtendedMasterSecret | Should -BeFalse
        ($result.WireChain.Thumbprint -join ',') | Should -Be ($script:chain.Leaf.Thumbprint, $script:chain.Intermediate.Thumbprint -join ',')
        $result.WireChain[0].PSObject.TypeNames[0] | Should -Be 'CertToolbox.CertificateInfo'
    }

    It 'adds up the connections made' {
        # suites: 1 + 1 + 1 + 4 + 3, groups: 3 + 11
        (Get-CertToolboxTlsCapability -HostName 'server.test.example').ConnectionCount | Should -Be 24
    }

    It 'leaves the features empty for a server that only accepts TLS 1.3' {
        Mock -ModuleName Posh-CertToolbox Find-CertToolboxServerCipherSuite {
            if ($Protocol -eq 'Tls13') { return Get-TestSuiteScan -Protocol Tls13 -CipherSuite 0x1301 }
            Get-TestSuiteScan -Protocol $Protocol -Reason 'refused'
        }

        $result = Get-CertToolboxTlsCapability -HostName 'server.test.example'

        $result.OcspStapling | Should -BeNullOrEmpty
        $result.SecureRenegotiation | Should -BeNullOrEmpty
        $result.ExtendedMasterSecret | Should -BeNullOrEmpty
        $result.WireChain | Should -BeNullOrEmpty
        ($result.Group.Protocol | Select-Object -Unique) | Should -Be 'Tls13'
    }

    It 'does not state whether the server staples when its answer could not be read to the end' {
        Mock -ModuleName Posh-CertToolbox Find-CertToolboxServerCipherSuite {
            if ($Protocol -eq 'Tls12') { return Get-TestSuiteScan -Protocol Tls12 -CipherSuite 0xC030 -Incomplete }
            Get-TestSuiteScan -Protocol $Protocol -Reason 'refused'
        }

        $result = Get-CertToolboxTlsCapability -HostName 'server.test.example'

        $result.OcspStapling | Should -BeNullOrEmpty
        $result.SecureRenegotiation | Should -BeTrue
    }

    It 'probes only the versions asked for, in version order, and passes the connection settings on' {
        $result = Get-CertToolboxTlsCapability -HostName '192.0.2.10' -Port 8443 -TargetHost 'server.test.example' -Protocol Tls13, Tls12 -TimeoutSec 4

        ($result.Protocol.Protocol -join ',') | Should -Be 'Tls12,Tls13'
        Should -Invoke -ModuleName Posh-CertToolbox Find-CertToolboxServerCipherSuite -Times 2 -Exactly -ParameterFilter {
            $Connection.HostName -eq '192.0.2.10' -and $Connection.Port -eq 8443 -and $Connection.TargetHost -eq 'server.test.example' -and
            $Connection.TimeoutMs -eq 4000 -and -not $Connection.ContainsKey('StartTls')
        }
        Should -Invoke -ModuleName Posh-CertToolbox Find-CertToolboxServerGroup -Times 2 -Exactly -ParameterFilter { $Connection.Port -eq 8443 }
    }

    It 'passes StartTls on, defaults to its port, and reports it' {
        $result = Get-CertToolboxTlsCapability -HostName 'mail.test.example' -StartTls Smtp -SmtpEhloName 'client.example' -Protocol Tls12

        $result.Port | Should -Be 25
        $result.StartTls | Should -Be 'Smtp'
        Should -Invoke -ModuleName Posh-CertToolbox Find-CertToolboxServerCipherSuite -Times 1 -Exactly -ParameterFilter {
            $Connection.StartTls -eq 'Smtp' -and $Connection.Port -eq 25 -and $Connection.SmtpEhloName -eq 'client.example'
        }

        (Get-CertToolboxTlsCapability -HostName 'mail.test.example' -StartTls Smtp -Port 587 -Protocol Tls12).Port | Should -Be 587
        (Get-CertToolboxTlsCapability -HostName 'www.test.example' -Protocol Tls12).StartTls | Should -BeNullOrEmpty
    }

    It 'scans each address of the name with EveryAddress, and none in particular by default' {
        Mock -ModuleName Posh-CertToolbox Resolve-CertToolboxHostAddress {
            [System.Net.IPAddress]::Parse('192.0.2.20')
            [System.Net.IPAddress]::Parse('2001:db8::2')
        }

        Get-CertToolboxTlsCapability -HostName 'server.test.example' -Protocol Tls12 | Out-Null
        Should -Invoke -ModuleName Posh-CertToolbox Resolve-CertToolboxHostAddress -Times 0 -Exactly
        Should -Invoke -ModuleName Posh-CertToolbox Find-CertToolboxServerCipherSuite -Times 1 -Exactly -ParameterFilter { -not $Connection.ContainsKey('Address') }

        $results = @(Get-CertToolboxTlsCapability -HostName 'many.test.example' -EveryAddress -AddressFamily IPv4 -Protocol Tls12)

        $results.Count | Should -Be 2
        @($results | Where-Object HostName -ne 'many.test.example') | Should -BeNullOrEmpty
        Should -Invoke -ModuleName Posh-CertToolbox Resolve-CertToolboxHostAddress -Times 1 -Exactly -ParameterFilter { $AddressFamily -eq 'IPv4' }
        foreach ($expected in '192.0.2.20', '2001:db8::2') {
            Should -Invoke -ModuleName Posh-CertToolbox Find-CertToolboxServerCipherSuite -Times 1 -Exactly -ParameterFilter {
                "$($Connection.Address)" -eq $expected -and $Connection.AddressFamily -eq 'IPv4'
            }
            Should -Invoke -ModuleName Posh-CertToolbox Find-CertToolboxServerGroup -Times 1 -Exactly -ParameterFilter { "$($Connection.Address)" -eq $expected }
        }
    }

    It 'names the address in the error when one address cannot be reached, and reports a name that does not resolve' {
        Mock -ModuleName Posh-CertToolbox Resolve-CertToolboxHostAddress {
            [System.Net.IPAddress]::Parse('192.0.2.20')
            [System.Net.IPAddress]::Parse('192.0.2.21')
        } -ParameterFilter { $HostName -eq 'many.test.example' }
        Mock -ModuleName Posh-CertToolbox Resolve-CertToolboxHostAddress { throw [System.Net.Sockets.SocketException]::new([int][System.Net.Sockets.SocketError]::HostNotFound) } -ParameterFilter { $HostName -eq 'gone.test.example' }
        Mock -ModuleName Posh-CertToolbox Find-CertToolboxServerCipherSuite {
            Get-TestSuiteScan -Protocol $Protocol -Reason 'connection refused' -ConnectFailed
        } -ParameterFilter { "$($Connection.Address)" -eq '192.0.2.21' }

        $output = 'gone.test.example', 'many.test.example' | Get-CertToolboxTlsCapability -EveryAddress -Protocol Tls12 2>&1

        $errors = @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
        ($errors.TargetObject -join ',') | Should -Be 'gone.test.example:443,many.test.example [192.0.2.21]:443'
        @($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }).Count | Should -Be 1
    }

    It 'writes a non-terminating error for an endpoint it cannot reach, and still scans the others' {
        Mock -ModuleName Posh-CertToolbox Find-CertToolboxServerCipherSuite {
            Get-TestSuiteScan -Protocol $Protocol -Reason 'No such host is known.' -ConnectFailed
        } -ParameterFilter { $Connection.HostName -eq 'down.test.example' }

        $output = 'down.test.example', 'server.test.example' | Get-CertToolboxTlsCapability 2>&1

        $errors = @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
        $results = @($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] })
        $errors.Count | Should -Be 1
        $errors[0].FullyQualifiedErrorId | Should -BeLike 'TlsProbeFailed*'
        $errors[0].TargetObject | Should -Be 'down.test.example:443'
        $errors[0].Exception.Message | Should -Be 'No such host is known.'
        $results.Count | Should -Be 1
        $results[0].HostName | Should -Be 'server.test.example'
        # The unreachable host is given up at the first probe, not probed five times.
        Should -Invoke -ModuleName Posh-CertToolbox Find-CertToolboxServerCipherSuite -Times 1 -Exactly -ParameterFilter { $Connection.HostName -eq 'down.test.example' }
    }

    It 'returns a result, not an error, for a server that answers but accepts nothing' {
        Mock -ModuleName Posh-CertToolbox Find-CertToolboxServerCipherSuite {
            Get-TestSuiteScan -Protocol $Protocol -Reason 'The server did not answer with a TLS record.'
        }

        $result = Get-CertToolboxTlsCapability -HostName 'plain.test.example' -Protocol Tls12, Tls13

        @($result.Protocol | Where-Object Accepted) | Should -BeNullOrEmpty
        $result.CipherSuite | Should -BeNullOrEmpty
        $result.Group | Should -BeNullOrEmpty
        Should -Invoke -ModuleName Posh-CertToolbox Find-CertToolboxServerGroup -Times 0 -Exactly
    }

    It 'logs the invocation at Debug, a summary at Information and a failure at Error' {
        Mock -ModuleName Posh-CertToolbox Find-CertToolboxServerCipherSuite {
            Get-TestSuiteScan -Protocol $Protocol -Reason 'connection refused' -ConnectFailed
        } -ParameterFilter { $Connection.HostName -eq 'down.test.example' }

        'server.test.example', 'down.test.example' | Get-CertToolboxTlsCapability -ErrorAction SilentlyContinue | Out-Null

        Should -Invoke -ModuleName Posh-CertToolbox Write-CertToolboxLog -Times 1 -Exactly -ParameterFilter {
            $Level -eq 'Debug' -and $CmdletName -eq 'Get-CertToolboxTlsCapability'
        }
        Should -Invoke -ModuleName Posh-CertToolbox Write-CertToolboxLog -Times 1 -Exactly -ParameterFilter {
            $Level -eq 'Information' -and $Target -eq 'server.test.example:443' -and
            $Message -eq 'Accepted versions: Tls12, Tls13; 5 cipher suite(s), 1 weak; 24 connection(s).'
        }
        Should -Invoke -ModuleName Posh-CertToolbox Write-CertToolboxLog -Times 1 -Exactly -ParameterFilter {
            $Level -eq 'Error' -and $Target -eq 'down.test.example:443' -and $Message -like '*connection refused*'
        }
    }
}

# Real servers: this is what checks the hand-built hello and the decoding of real answers.
Describe 'Get-CertToolboxTlsCapability against real endpoints' -Tag Integration {
    It 'finds the versions, suites, groups and chain of a modern server' {
        $result = Get-CertToolboxTlsCapability -HostName 'www.google.com'

        ($result.Protocol | Where-Object Protocol -eq 'Ssl3').Accepted | Should -BeFalse
        ($result.Protocol | Where-Object Protocol -eq 'Tls12').Accepted | Should -BeTrue
        ($result.Protocol | Where-Object Protocol -eq 'Tls13').Accepted | Should -BeTrue
        @($result.CipherSuite | Where-Object Protocol -eq 'Tls13').Name | Should -Contain 'TLS_AES_128_GCM_SHA256'
        @($result.CipherSuite | Where-Object { $_.Protocol -eq 'Tls12' -and $_.ForwardSecrecy -and $_.AuthenticatedEncryption }).Count | Should -BeGreaterThan 0
        @($result.CipherSuite | Where-Object { $_.Name -like '0x*' }) | Should -BeNullOrEmpty
        @($result.Group | Where-Object Protocol -eq 'Tls13').Name | Should -Contain 'x25519'
        $result.WireChain[0].SubjectAlternativeName | Should -Contain 'www.google.com'
        $result.SecureRenegotiation | Should -BeTrue
    }

    It 'shows that a server limited to TLS 1.2 refuses every other version, each with a reason' {
        $result = Get-CertToolboxTlsCapability -HostName 'tls-v1-2.badssl.com' -Port 1012

        (@($result.Protocol | Where-Object Accepted).Protocol -join ',') | Should -Be 'Tls12'
        @($result.Protocol | Where-Object { -not $_.Accepted -and -not $_.Reason }) | Should -BeNullOrEmpty
        @($result.CipherSuite).Count | Should -BeGreaterThan 1
    }

    It 'finds the weak suites of a server that only offers RC4' {
        $result = Get-CertToolboxTlsCapability -HostName 'rc4.badssl.com' -Protocol Tls12

        $suites = @($result.CipherSuite)
        $suites.Count | Should -BeGreaterThan 0
        @($suites | Where-Object { -not $_.Weak }) | Should -BeNullOrEmpty
        @($suites | Where-Object { $_.Name -notlike '*_RC4_*' }) | Should -BeNullOrEmpty
    }

    It 'scans a mail server through SMTP STARTTLS' {
        $result = Get-CertToolboxTlsCapability -HostName 'smtp.gmail.com' -Port 587 -StartTls Smtp -Protocol Tls12, Tls13

        $result.StartTls | Should -Be 'Smtp'
        @($result.Protocol | Where-Object Accepted).Count | Should -BeGreaterThan 0
        @($result.CipherSuite).Count | Should -BeGreaterThan 0
    }

    It 'reports a plain-text service as answering without TLS, not as an error' {
        $result = Get-CertToolboxTlsCapability -HostName 'www.google.com' -Port 80 -Protocol Tls12 -TimeoutSec 5

        $result.Protocol[0].Accepted | Should -BeFalse
        $result.Protocol[0].Reason | Should -Not -BeNullOrEmpty
    }
}

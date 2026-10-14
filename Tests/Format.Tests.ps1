BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $script:formatPath = Join-Path $script:repoRoot 'Posh-CertToolbox.format.ps1xml'
    Import-Module (Join-Path $script:repoRoot 'Posh-CertToolbox.psd1') -Force
    . (Join-Path $PSScriptRoot 'TestHelper.ps1')
    $script:chain = Get-TestCertificateChain

    # The text a value gives when it falls to the console.
    function Get-TestDisplay {
        param([Parameter(ValueFromPipeline)] $InputObject)
        begin { $items = [System.Collections.Generic.List[object]]::new() }
        process { $items.Add($InputObject) }
        end { ($items | Out-String -Width 250) }
    }

    # The property names of the object literal that carries a type name in the module's code.
    function Get-TestSourceProperty {
        param([string] $TypeName)

        $pattern = "PSTypeName\s*=\s*'$([regex]::Escape($TypeName))'"
        foreach ($file in (Get-ChildItem -Path (Join-Path $script:repoRoot 'Public'), (Join-Path $script:repoRoot 'Private') -Filter '*.ps1' -File -Recurse)) {
            $lines = [System.IO.File]::ReadAllLines($file.FullName)
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -notmatch $pattern) {
                    continue
                }
                for ($j = $i + 1; $j -lt $lines.Count -and $lines[$j] -notmatch '^\s*\}'; $j++) {
                    if ($lines[$j] -match '^\s*(\w+)\s*=') {
                        $Matches[1]
                    }
                }
                return
            }
        }
    }
}

Describe 'Format file' -Tag Unit {
    BeforeAll {
        $script:format = [xml][System.IO.File]::ReadAllText($script:formatPath)
        $script:views = @($script:format.Configuration.ViewDefinitions.View)
    }

    It 'is declared in the manifest and loaded with the module' {
        $module = Import-Module (Join-Path $script:repoRoot 'Posh-CertToolbox.psd1') -Force -PassThru

        @($module.ExportedFormatFiles | ForEach-Object { [System.IO.Path]::GetFileName($_) }) | Should -Contain 'Posh-CertToolbox.format.ps1xml'
    }

    It 'has a view for every type name the module gives to an object, and for no other' {
        $sourceTypes = Get-ChildItem -Path (Join-Path $script:repoRoot 'Public'), (Join-Path $script:repoRoot 'Private') -Filter '*.ps1' -File -Recurse |
            ForEach-Object { [regex]::Matches([System.IO.File]::ReadAllText($_.FullName), "PSTypeName\s*=\s*'([^']+)'") } |
            ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
        $viewTypes = $script:views | ForEach-Object { $_.ViewSelectedBy.TypeName } | Sort-Object -Unique

        ($viewTypes -join ',') | Should -Be ($sourceTypes -join ',')
    }

    It 'only names properties that the objects have' {
        $unknown = foreach ($view in $script:views) {
            $typeName = $view.ViewSelectedBy.TypeName
            $known = @(Get-TestSourceProperty -TypeName $typeName)
            foreach ($node in $view.SelectNodes('.//PropertyName')) {
                if ($known -notcontains $node.InnerText) {
                    "$typeName.$($node.InnerText)"
                }
            }
        }

        $known.Count | Should -BeGreaterThan 0
        $unknown | Should -BeNullOrEmpty
    }

    It 'gives every table as many columns as it has headers' {
        foreach ($view in ($script:views | Where-Object { $_.TableControl })) {
            $headers = @($view.TableControl.TableHeaders.TableColumnHeader).Count
            $items = @($view.TableControl.TableRowEntries.TableRowEntry.TableColumnItems.TableColumnItem).Count

            $items | Should -Be $headers -Because $view.Name
        }
    }
}

Describe 'Default display' -Tag Unit {
    BeforeEach {
        Mock -ModuleName Posh-CertToolbox Read-CertToolboxConfigFile { [PSCustomObject]@{ version = '1.0' } }
        Mock -ModuleName Posh-CertToolbox Write-CertToolboxLog {}
    }

    Context 'Get-CertToolboxTlsCertificate' {
        BeforeEach {
            $script:probeResult = Get-TestTlsProbeResult `
                -ServerCertificate $script:chain.Leaf, $script:chain.Intermediate `
                -LocalCertificate $script:chain.Leaf, $script:chain.Intermediate, $script:chain.Root
            Mock -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe { $script:probeResult }
        }

        It 'shows a short summary and leaves the object whole' {
            $result = Get-CertToolboxTlsCertificate -HostName 'test.example'
            $text = $result | Get-TestDisplay

            $text | Should -Match '(?m)^Endpoint\s+: test\.example:443\s*$'
            $text | Should -Match '(?m)^RemoteAddress\s+: 192\.0\.2\.10\s*$'
            $text | Should -Match '(?m)^Protocol\s+: Tls13\s*$'
            $text | Should -Match '(?m)^Cipher\s+: TLS_AES_256_GCM_SHA384\s*$'
            $text | Should -Match '(?m)^ValidationPassed\s+: True\s*$'
            $text | Should -Match "(?m)^Subject\s+: $([regex]::Escape($script:chain.Leaf.Subject))\s*$"
            $text | Should -Match "(?m)^NotAfter\s+: $($script:chain.Leaf.NotAfter.ToString('yyyy-MM-dd')) \(-?\d+ days\)\s*$"
            $text | Should -Match '(?m)^Chain\s+: 2 sent by the server, 3 in the local chain\s*$'
            @($text.Trim() -split "`n").Count | Should -BeLessThan 15

            @($result.PSObject.Properties).Count | Should -Be 23
            ($result | Format-List * | Out-String) | Should -Match '(?m)^ElapsedMs\s+: 12'
        }

        It 'leaves out the lines that have nothing to say' {
            $text = Get-CertToolboxTlsCertificate -HostName 'test.example' | Get-TestDisplay

            $text | Should -Not -Match '(?m)^(TargetHost|StartTls|PolicyError|ChainStatus|MissingIntermediate|ServerSentRoot|UnusedServerCertificate|UrlTest)\s+:'
        }

        It 'shows what is wrong with a chain' {
            $script:probeResult = Get-TestTlsProbeResult -ServerCertificate $script:chain.Leaf, $script:chain.Root `
                -LocalCertificate $script:chain.Leaf, $script:chain.Intermediate, $script:chain.Root `
                -PolicyErrors 'RemoteCertificateChainErrors' -ChainStatus 'UntrustedRoot'

            $text = Get-CertToolboxTlsCertificate -HostName '192.0.2.10' -TargetHost 'test.example' | Get-TestDisplay

            $text | Should -Match '(?m)^TargetHost\s+: test\.example\s*$'
            $text | Should -Match '(?m)^ValidationPassed\s+: False\s*$'
            $text | Should -Match '(?m)^PolicyError\s+: RemoteCertificateChainErrors\s*$'
            $text | Should -Match '(?m)^ChainStatus\s+: UntrustedRoot\s*$'
            $text | Should -Match "(?m)^MissingIntermediate\s+: $([regex]::Escape($script:chain.Intermediate.Subject))\s*$"
            $text | Should -Match '(?m)^ServerSentRoot\s+: True\s*$'
        }

        It 'counts the URL tests and those with a problem' {
            Mock -ModuleName Posh-CertToolbox Invoke-CertToolboxCertificateUrlTest {
                foreach ($outcome in 'NotRevoked', 'Good', 'Failed') {
                    [PSCustomObject]@{
                        PSTypeName = 'CertToolbox.CertificateUrlTest'
                        Subject    = 'CN=leaf.test.example, O=Test, C=FR'
                        Thumbprint = 'AA'
                        Chain      = 'Both'
                        Type       = 'Crl'
                        Url        = "http://pki.test.example/$outcome"
                        Result     = $outcome
                        Signature  = 'Valid'
                    }
                }
            }

            $result = Get-CertToolboxTlsCertificate -HostName 'test.example' -TestCertificateUrl

            ($result | Get-TestDisplay) | Should -Match '(?m)^UrlTest\s+: 3 run, 1 with a problem\s*$'

            $rows = $result.UrlTest | Get-TestDisplay
            $rows | Should -Match '(?m)^Certificate\s+Chain\s+Type\s+Result\s+Signature\s+Url\s*$'
            $rows | Should -Match '(?m)^CN=leaf\.test\.example\s+Both\s+Crl\s+Failed\s+Valid\s+http://pki\.test\.example/Failed\s*$'
        }

        It 'shows one line per result with Format-Table' {
            $text = Get-CertToolboxTlsCertificate -HostName 'a.test.example', 'b.test.example' | Format-Table | Out-String -Width 250

            $text | Should -Match '(?m)^HostName\s+Port\s+RemoteAddress\s+Protocol\s+Valid\s+Days\s+Subject\s*$'
            $text | Should -Match "(?m)^a\.test\.example\s+443\s+192\.0\.2\.10\s+Tls13\s+True\s+-?\d+\s+$([regex]::Escape($script:chain.Leaf.Subject))\s*$"
            $text | Should -Match '(?m)^b\.test\.example\s+443\s'
        }

        It 'shows the certificates of a chain as a table' {
            $result = Get-CertToolboxTlsCertificate -HostName 'test.example'
            $text = $result.LocalChain | Get-TestDisplay

            $text | Should -Match '(?m)^Subject\s+NotAfter\s+Days\s+Status\s+Issuer\s*$'
            @($text.Trim() -split "`n").Count | Should -Be 5
            $text | Should -Match ([regex]::Escape($script:chain.Root.Subject))
        }
    }

    Context 'Test-CertToolboxTlsProtocol' {
        It 'shows one line per protocol version' {
            $script:probeResult = Get-TestTlsProbeResult -ServerCertificate $script:chain.Leaf -LocalCertificate $script:chain.Leaf -Protocol 'Tls12'
            Mock -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe { throw [System.InvalidOperationException]::new('refused by the server') }
            Mock -ModuleName Posh-CertToolbox Invoke-CertToolboxTlsProbe { $script:probeResult } -ParameterFilter {
                $SslProtocol -eq [System.Security.Authentication.SslProtocols]::Tls12
            }

            $text = Test-CertToolboxTlsProtocol -HostName 'test.example' -Protocol Tls11, Tls12 | Get-TestDisplay

            $text | Should -Match '(?m)^HostName\s+Port\s+RemoteAddress\s+Protocol\s+Negotiated\s+ErrorMessage\s*$'
            $text | Should -Match '(?m)^test\.example\s+443\s+Tls11\s+False\s+refused by the server\s*$'
            $text | Should -Match '(?m)^test\.example\s+443\s+192\.0\.2\.10\s+Tls12\s+True\s*$'
        }
    }

    Context 'Get-CertToolboxTlsCapability' {
        BeforeEach {
            Mock -ModuleName Posh-CertToolbox Find-CertToolboxServerCipherSuite {
                $suites = [int[]]@()
                $reason = "The server refused with the alert 'protocol_version'."
                if ($Protocol -eq 'Tls12') {
                    $suites = [int[]](0xC030, 0x0005)
                    $reason = $null
                }
                $first = $null
                if ($suites.Count -gt 0) {
                    $first = [PSCustomObject]@{
                        RemoteAddress        = '192.0.2.10'
                        SecureRenegotiation  = $true
                        ExtendedMasterSecret = $false
                        OcspStapled          = $true
                        Complete             = $true
                        Certificate          = @($script:chain.Leaf, $script:chain.Intermediate)
                    }
                }
                [PSCustomObject]@{
                    Protocol          = $Protocol
                    Accepted          = ($suites.Count -gt 0)
                    Reason            = $reason
                    CipherSuite       = $suites
                    ServerCipherOrder = $true
                    FirstAnswer       = $first
                    ConnectFailed     = $false
                    ConnectionCount   = 3
                }
            }
            Mock -ModuleName Posh-CertToolbox Find-CertToolboxServerGroup { [PSCustomObject]@{ Group = [int[]](29, 23); ConnectionCount = 3 } }
        }

        It 'shows a summary of what the server accepts' {
            $result = Get-CertToolboxTlsCapability -HostName 'server.test.example' -Protocol Tls11, Tls12
            $text = $result | Get-TestDisplay

            $text | Should -Match '(?m)^Endpoint\s+: server\.test\.example:443\s*$'
            $text | Should -Match '(?m)^Protocol\s+: Tls12\s*$'
            $text | Should -Match '(?m)^CipherSuite\s+: 2 accepted, 1 weak\s*$'
            $text | Should -Match '(?m)^Group\s+: x25519, secp256r1\s*$'
            $text | Should -Match '(?m)^OcspStapling\s+: True\s*$'
            $text | Should -Match '(?m)^WireChain\s+: 2 certificate\(s\)\s*$'

            ($result | Format-Table | Out-String -Width 250) | Should -Match '(?m)^server\.test\.example\s+443\s+192\.0\.2\.10\s+Tls12\s+2\s+1\s*$'
        }

        It 'gives each kind of row its type name and its table' {
            $result = Get-CertToolboxTlsCapability -HostName 'server.test.example' -Protocol Tls11, Tls12

            $result.Protocol[0].PSObject.TypeNames[0] | Should -Be 'CertToolbox.TlsCapabilityProtocol'
            $result.CipherSuite[0].PSObject.TypeNames[0] | Should -Be 'CertToolbox.TlsCapabilityCipherSuite'
            $result.Group[0].PSObject.TypeNames[0] | Should -Be 'CertToolbox.TlsCapabilityGroup'

            $protocol = $result.Protocol | Get-TestDisplay
            $protocol | Should -Match '(?m)^Protocol\s+Accepted\s+CipherSuiteCount\s+ServerCipherOrder\s+Reason\s*$'
            $protocol | Should -Match "(?m)^Tls11\s+False\s+0\s+True\s+The server refused with the alert 'protocol_version'\.\s*$"

            $suite = $result.CipherSuite | Get-TestDisplay
            $suite | Should -Match '(?m)^Protocol\s+Order\s+Name\s+Code\s+ForwardSecrecy\s+AuthenticatedEncryption\s+Weak\s*$'
            $suite | Should -Match '(?m)^Tls12\s+2\s+TLS_RSA_WITH_RC4_128_SHA\s+0x0005\s+False\s+False\s+True\s*$'

            ($result.Group | Get-TestDisplay) | Should -Match '(?m)^Tls12\s+x25519\s+29\s*$'
        }
    }

    Context 'Get-CertToolboxCaaRecord' {
        It 'shows who may issue, and nothing about a restriction that does not exist' {
            Mock -ModuleName Posh-CertToolbox Find-CertToolboxCaaRecordSet {
                [PSCustomObject]@{
                    RecordSetName = 'example.com'
                    Record        = @(
                        [PSCustomObject]@{ Flag = 0; Critical = $false; Tag = 'issue'; Value = 'ca-one.example'; CaDomain = 'ca-one.example'; Ttl = 300 },
                        [PSCustomObject]@{ Flag = 0; Critical = $false; Tag = 'issue'; Value = 'ca-two.example'; CaDomain = 'ca-two.example'; Ttl = 300 }
                    )
                    QueriedName   = @('www.example.com', 'example.com')
                }
            } -ParameterFilter { $Name -eq 'www.example.com' }
            Mock -ModuleName Posh-CertToolbox Find-CertToolboxCaaRecordSet {
                [PSCustomObject]@{ RecordSetName = $null; Record = @(); QueriedName = @('free.example') }
            } -ParameterFilter { $Name -eq 'free.example' }

            $restricted = Get-CertToolboxCaaRecord -Name 'www.example.com' | Get-TestDisplay
            $restricted | Should -Match '(?m)^Name\s+: www\.example\.com\s*$'
            $restricted | Should -Match '(?m)^RecordSetName\s+: example\.com\s*$'
            $restricted | Should -Match '(?m)^Issue\s+: ca-one\.example, ca-two\.example\s*$'

            $free = Get-CertToolboxCaaRecord -Name 'free.example' | Get-TestDisplay
            $free | Should -Match '(?m)^HasCaaRecord\s+: False\s*$'
            $free | Should -Match '(?m)^IssueRestricted\s+: False\s*$'
            $free | Should -Not -Match '(?m)^(RecordSetName|Issue|IssueWild|Iodef)\s+:'
        }
    }
}

Describe 'Default display of real results' -Tag Integration {
    It 'shows a real endpoint in a few lines, and its chain as a table' {
        $result = Get-CertToolboxTlsCertificate -HostName 'www.google.com'
        $text = $result | Out-String -Width 250

        $text | Should -Match '(?m)^Endpoint\s+: www\.google\.com:443\s*$'
        $text | Should -Match '(?m)^Subject\s+: CN=www\.google\.com'
        $text | Should -Match '(?m)^Chain\s+: \d+ sent by the server, \d+ in the local chain\s*$'
        @($text.Trim() -split "`n").Count | Should -BeLessThan 20

        ($result.ServerChain | Out-String -Width 250) | Should -Match '(?m)^Subject\s+NotAfter\s+Days\s+Status\s+Issuer\s*$'
    }
}

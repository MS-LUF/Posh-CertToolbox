BeforeDiscovery {
    Import-Module (Join-Path $PSScriptRoot '../../Posh-CertToolbox.psd1') -Force
}

Describe 'Private/Dns' -Tag Unit {
    InModuleScope 'Posh-CertToolbox' {
        Describe 'Invoke-CertToolboxDnsQuery' {
            It 'queries the DNS-over-HTTPS endpoint with the escaped name and type' {
                Mock Invoke-RestMethod { [PSCustomObject]@{ Status = 0 } }

                $response = Invoke-CertToolboxDnsQuery -Name 'a b.example.com' -Type 'CAA' -TimeoutSec 7
                $response.Status | Should -Be 0

                Should -Invoke Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
                    # AbsoluteUri, not the string form: Uri.ToString() unescapes %20 back to a space.
                    ([uri]$Uri).AbsoluteUri -eq 'https://dns.google/resolve?name=a%20b.example.com&type=CAA' -and $TimeoutSec -eq 7
                }
            }
        }

        Describe 'ConvertFrom-CertToolboxCaaData' {
            It 'parses a quoted issue record' {
                $record = ConvertFrom-CertToolboxCaaData -Data '0 issue "letsencrypt.org"'
                $record.Flag | Should -Be 0
                $record.Critical | Should -BeFalse
                $record.Tag | Should -Be 'issue'
                $record.Value | Should -Be 'letsencrypt.org'
                $record.CaDomain | Should -Be 'letsencrypt.org'
            }

            It 'separates the CA domain from its parameters' {
                $record = ConvertFrom-CertToolboxCaaData -Data '0 issuewild "ca.example; accounturi=https://ca.example/acct/1"'
                $record.Tag | Should -Be 'issuewild'
                $record.CaDomain | Should -Be 'ca.example'
                $record.Value | Should -Be 'ca.example; accounturi=https://ca.example/acct/1'
            }

            It 'gives an empty CA domain for a record that forbids issuance' {
                $record = ConvertFrom-CertToolboxCaaData -Data '0 issue ";"'
                $record.CaDomain | Should -BeNullOrEmpty
                $record.Value | Should -Be ';'
            }

            It 'detects the issuer-critical flag and lower-cases the tag' {
                $record = ConvertFrom-CertToolboxCaaData -Data '128 ISSUE "ca.example"'
                $record.Critical | Should -BeTrue
                $record.Tag | Should -Be 'issue'
            }

            It 'keeps the value of a tag it does not interpret, with no CA domain' {
                $record = ConvertFrom-CertToolboxCaaData -Data '0 iodef "mailto:security@example.com"'
                $record.Value | Should -Be 'mailto:security@example.com'
                $record.CaDomain | Should -BeNullOrEmpty
            }

            It 'warns and returns nothing for data it cannot parse' {
                $record = ConvertFrom-CertToolboxCaaData -Data 'garbage' -WarningVariable warnings -WarningAction SilentlyContinue
                $record | Should -BeNullOrEmpty
                $warnings | Should -Not -BeNullOrEmpty
            }
        }

        Describe 'Find-CertToolboxCaaRecordSet' {
            It 'returns the records found on the name itself without climbing' {
                Mock Invoke-CertToolboxDnsQuery {
                    [PSCustomObject]@{ Status = 0; Answer = @([PSCustomObject]@{ name = 'www.example.com.'; type = 257; TTL = 300; data = '0 issue "ca.example"' }) }
                }

                $result = Find-CertToolboxCaaRecordSet -Name 'www.example.com'

                $result.RecordSetName | Should -Be 'www.example.com'
                @($result.Record).Count | Should -Be 1
                $result.Record[0].CaDomain | Should -Be 'ca.example'
                $result.Record[0].Ttl | Should -Be 300
                ($result.QueriedName -join ',') | Should -Be 'www.example.com'
                Should -Invoke Invoke-CertToolboxDnsQuery -Times 1 -Exactly
            }

            It 'climbs to the parent domain, past a name that does not exist' {
                Mock Invoke-CertToolboxDnsQuery { [PSCustomObject]@{ Status = 3 } } -ParameterFilter { $Name -eq 'a.b.example.com' }
                Mock Invoke-CertToolboxDnsQuery { [PSCustomObject]@{ Status = 0 } } -ParameterFilter { $Name -eq 'b.example.com' }
                Mock Invoke-CertToolboxDnsQuery {
                    [PSCustomObject]@{ Status = 0; Answer = @([PSCustomObject]@{ name = 'example.com.'; type = 257; TTL = 60; data = '0 issue "ca.example"' }) }
                } -ParameterFilter { $Name -eq 'example.com' }

                $result = Find-CertToolboxCaaRecordSet -Name 'a.b.example.com.'

                $result.RecordSetName | Should -Be 'example.com'
                ($result.QueriedName -join ',') | Should -Be 'a.b.example.com,b.example.com,example.com'
            }

            It 'ignores the CNAME records of a response and keeps climbing when no CAA record came with them' {
                Mock Invoke-CertToolboxDnsQuery {
                    [PSCustomObject]@{ Status = 0; Answer = @([PSCustomObject]@{ name = 'www.example.com.'; type = 5; TTL = 60; data = 'target.example.net.' }) }
                } -ParameterFilter { $Name -eq 'www.example.com' }
                Mock Invoke-CertToolboxDnsQuery {
                    [PSCustomObject]@{ Status = 0; Answer = @([PSCustomObject]@{ name = 'example.com.'; type = 257; TTL = 60; data = '0 issue "ca.example"' }) }
                } -ParameterFilter { $Name -eq 'example.com' }

                (Find-CertToolboxCaaRecordSet -Name 'www.example.com').RecordSetName | Should -Be 'example.com'
            }

            It 'queries up to the top-level domain and reports no record set when none is found' {
                Mock Invoke-CertToolboxDnsQuery { [PSCustomObject]@{ Status = 0 } }

                $result = Find-CertToolboxCaaRecordSet -Name 'www.example.com'

                $result.RecordSetName | Should -BeNullOrEmpty
                $result.Record | Should -BeNullOrEmpty
                ($result.QueriedName -join ',') | Should -Be 'www.example.com,example.com,com'
            }

            It 'throws on a DNS failure instead of treating it as no record' {
                Mock Invoke-CertToolboxDnsQuery { [PSCustomObject]@{ Status = 2 } }

                { Find-CertToolboxCaaRecordSet -Name 'www.example.com' } | Should -Throw '*response code 2*'
            }
        }
    }
}

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../Posh-CertToolbox.psd1') -Force

    function Get-TestCaaRecord {
        param([string] $Tag, [string] $Value, [string] $CaDomain)
        [PSCustomObject]@{ Flag = 0; Critical = $false; Tag = $Tag; Value = $Value; CaDomain = $CaDomain; Ttl = 300 }
    }
}

Describe 'Get-CertToolboxCaaRecord' -Tag Unit {
    BeforeEach {
        Mock -ModuleName Posh-CertToolbox Read-CertToolboxConfigFile { [PSCustomObject]@{ version = '1.0' } }
        Mock -ModuleName Posh-CertToolbox Write-CertToolboxLog {}
    }

    Context 'logging' {
        It 'logs the invocation at Debug, a result at Information and a failure at Error' {
            Mock -ModuleName Posh-CertToolbox Find-CertToolboxCaaRecordSet { throw 'DNS is down' } -ParameterFilter { $Name -eq 'bad.example.com' }
            Mock -ModuleName Posh-CertToolbox Find-CertToolboxCaaRecordSet {
                [PSCustomObject]@{
                    RecordSetName = 'example.com'
                    Record        = @((Get-TestCaaRecord -Tag 'issue' -Value 'ca-one.example' -CaDomain 'ca-one.example'))
                    QueriedName   = @('good.example.com', 'example.com')
                }
            } -ParameterFilter { $Name -eq 'good.example.com' }

            'bad.example.com', 'good.example.com' | Get-CertToolboxCaaRecord -ErrorAction SilentlyContinue | Out-Null

            Should -Invoke -ModuleName Posh-CertToolbox Write-CertToolboxLog -Times 1 -Exactly -ParameterFilter {
                $Level -eq 'Debug' -and $CmdletName -eq 'Get-CertToolboxCaaRecord'
            }
            Should -Invoke -ModuleName Posh-CertToolbox Write-CertToolboxLog -Times 1 -Exactly -ParameterFilter {
                $Level -eq 'Information' -and $Target -eq 'good.example.com' -and $Message -like "CAA record set found on 'example.com': issue=``[ca-one.example``]*"
            }
            Should -Invoke -ModuleName Posh-CertToolbox Write-CertToolboxLog -Times 1 -Exactly -ParameterFilter {
                $Level -eq 'Error' -and $Target -eq 'bad.example.com' -and $Message -like '*DNS is down*'
            }
        }
    }

    Context 'a record set with issue records only' {
        BeforeEach {
            Mock -ModuleName Posh-CertToolbox Find-CertToolboxCaaRecordSet {
                [PSCustomObject]@{
                    RecordSetName = 'example.com'
                    Record        = @(
                        (Get-TestCaaRecord -Tag 'issue' -Value 'ca-one.example' -CaDomain 'ca-one.example'),
                        (Get-TestCaaRecord -Tag 'issue' -Value 'ca-two.example; account=1' -CaDomain 'ca-two.example'),
                        (Get-TestCaaRecord -Tag 'iodef' -Value 'mailto:security@example.com')
                    )
                    QueriedName   = @('www.example.com', 'example.com')
                }
            }
        }

        It 'lists the allowed CAs and where the record set was found' {
            $result = Get-CertToolboxCaaRecord -Name 'www.example.com'

            $result.PSObject.TypeNames[0] | Should -Be 'CertToolbox.CaaRecord'
            $result.Name | Should -Be 'www.example.com'
            $result.HasCaaRecord | Should -BeTrue
            $result.RecordSetName | Should -Be 'example.com'
            $result.IssueRestricted | Should -BeTrue
            ($result.Issue -join ',') | Should -Be 'ca-one.example,ca-two.example'
            ($result.Iodef -join ',') | Should -Be 'mailto:security@example.com'
            @($result.Record).Count | Should -Be 3
        }

        It 'applies the issue records to wildcard issuance when there is no issuewild record' {
            $result = Get-CertToolboxCaaRecord -Name 'www.example.com'

            $result.IssueWildRestricted | Should -BeTrue
            ($result.IssueWild -join ',') | Should -Be 'ca-one.example,ca-two.example'
        }

        It 'strips a wildcard prefix and a trailing dot before the lookup, keeping the name as given in the output' {
            $result = Get-CertToolboxCaaRecord -Name '*.example.com.'

            $result.Name | Should -Be '*.example.com.'
            Should -Invoke -ModuleName Posh-CertToolbox Find-CertToolboxCaaRecordSet -Times 1 -Exactly -ParameterFilter { $Name -eq 'example.com' }
        }

        It 'accepts several names from the pipeline and passes the timeout on' {
            $results = 'a.example.com', 'b.example.com' | Get-CertToolboxCaaRecord -TimeoutSec 3

            @($results).Count | Should -Be 2
            Should -Invoke -ModuleName Posh-CertToolbox Find-CertToolboxCaaRecordSet -Times 2 -Exactly -ParameterFilter { $TimeoutSec -eq 3 }
        }
    }

    Context 'a record set with issuewild records' {
        It 'gives issuewild precedence for wildcard issuance' {
            Mock -ModuleName Posh-CertToolbox Find-CertToolboxCaaRecordSet {
                [PSCustomObject]@{
                    RecordSetName = 'example.com'
                    Record        = @(
                        (Get-TestCaaRecord -Tag 'issue' -Value 'ca-one.example' -CaDomain 'ca-one.example'),
                        (Get-TestCaaRecord -Tag 'issuewild' -Value 'ca-wild.example' -CaDomain 'ca-wild.example')
                    )
                    QueriedName   = @('example.com')
                }
            }

            $result = Get-CertToolboxCaaRecord -Name 'example.com'

            ($result.Issue -join ',') | Should -Be 'ca-one.example'
            ($result.IssueWild -join ',') | Should -Be 'ca-wild.example'
        }

        It 'reports issuance as restricted to no CA at all for a record that names none' {
            Mock -ModuleName Posh-CertToolbox Find-CertToolboxCaaRecordSet {
                [PSCustomObject]@{
                    RecordSetName = 'example.com'
                    Record        = @((Get-TestCaaRecord -Tag 'issue' -Value ';' -CaDomain ''))
                    QueriedName   = @('example.com')
                }
            }

            $result = Get-CertToolboxCaaRecord -Name 'example.com'

            $result.IssueRestricted | Should -BeTrue
            $result.Issue | Should -BeNullOrEmpty
            $result.IssueWildRestricted | Should -BeTrue
            $result.IssueWild | Should -BeNullOrEmpty
        }
    }

    Context 'no record set anywhere' {
        It 'reports that issuance is not restricted' {
            Mock -ModuleName Posh-CertToolbox Find-CertToolboxCaaRecordSet {
                [PSCustomObject]@{ RecordSetName = $null; Record = @(); QueriedName = @('example.com', 'com') }
            }

            $result = Get-CertToolboxCaaRecord -Name 'example.com'

            $result.HasCaaRecord | Should -BeFalse
            $result.RecordSetName | Should -BeNullOrEmpty
            $result.IssueRestricted | Should -BeFalse
            $result.IssueWildRestricted | Should -BeFalse
            $result.Issue | Should -BeNullOrEmpty
            ($result.QueriedName -join ',') | Should -Be 'example.com,com'
        }
    }

    Context 'lookup failure' {
        It 'writes a non-terminating error for the failing name and still processes the others' {
            Mock -ModuleName Posh-CertToolbox Find-CertToolboxCaaRecordSet { throw 'DNS is down' } -ParameterFilter { $Name -eq 'bad.example.com' }
            Mock -ModuleName Posh-CertToolbox Find-CertToolboxCaaRecordSet {
                [PSCustomObject]@{ RecordSetName = $null; Record = @(); QueriedName = @('good.example.com') }
            } -ParameterFilter { $Name -eq 'good.example.com' }

            $output = 'bad.example.com', 'good.example.com' | Get-CertToolboxCaaRecord 2>&1

            $errors = @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
            $results = @($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] })
            $errors.Count | Should -Be 1
            $errors[0].FullyQualifiedErrorId | Should -BeLike 'CaaLookupFailed*'
            $errors[0].TargetObject | Should -Be 'bad.example.com'
            $results.Count | Should -Be 1
            $results[0].Name | Should -Be 'good.example.com'
        }
    }
}

Describe 'Get-CertToolboxCaaRecord against real DNS' -Tag Integration {
    It 'finds the record set of a name that has none itself on its parent domain' {
        $result = Get-CertToolboxCaaRecord -Name 'www.google.com'

        $result.HasCaaRecord | Should -BeTrue
        $result.RecordSetName | Should -Be 'google.com'
        $result.Issue | Should -Contain 'pki.goog'
    }
}

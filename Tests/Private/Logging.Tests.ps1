BeforeDiscovery {
    Import-Module (Join-Path $PSScriptRoot '../../Posh-CertToolbox.psd1') -Force
}

Describe 'Private/Logging' -Tag Unit {
    InModuleScope 'Posh-CertToolbox' {
        BeforeEach {
            $script:LoggingConfigWarned = $false
            $script:LoggingSinkFailed = $false
        }

        Describe 'Get-CertToolboxLoggingConfig' {
            It 'defaults Enabled to $false when Logging is absent' {
                $config = [PSCustomObject]@{ version = '1.0' }
                (Get-CertToolboxLoggingConfig -Config $config).Enabled | Should -Be $false
            }

            It 'passes through Enabled/MinimumLevel/Mode when valid' {
                $config = [PSCustomObject]@{
                    Logging = [PSCustomObject]@{ Enabled = $true; MinimumLevel = 'Debug'; Mode = 'EventLog' }
                }
                $result = Get-CertToolboxLoggingConfig -Config $config
                $result.Enabled | Should -Be $true
                $result.MinimumLevel | Should -Be 'Debug'
                $result.Mode | Should -Be 'EventLog'
            }

            It 'defaults every File/EventLog field when absent' {
                $config = [PSCustomObject]@{ Logging = [PSCustomObject]@{ Enabled = $true } }
                $result = Get-CertToolboxLoggingConfig -Config $config
                # Cross-platform default: computed via [System.IO.Path]::GetTempPath() rather
                # than a literal '%TEMP%\...' string, since TEMP does not exist as an
                # environment variable on Linux or macOS.
                $result.File.Path | Should -Be (Join-Path ([System.IO.Path]::GetTempPath()) 'Posh-CertToolbox')
                $result.File.FileName | Should -Be 'Posh-CertToolbox-{yyyyMMdd}.log'
                $result.EventLog.LogName | Should -Be 'Application'
                $result.EventLog.Source | Should -Be 'Posh-CertToolbox'
                $result.EventLog.EventIdInformation | Should -Be 1000
                $result.EventLog.EventIdWarning | Should -Be 2000
                $result.EventLog.EventIdError | Should -Be 3000
            }

            It 'falls back to Information and warns once on an invalid MinimumLevel' {
                Mock Write-Warning {}
                $config = [PSCustomObject]@{ Logging = [PSCustomObject]@{ MinimumLevel = 'Bogus' } }

                (Get-CertToolboxLoggingConfig -Config $config).MinimumLevel | Should -Be 'Information'
                Get-CertToolboxLoggingConfig -Config $config | Out-Null

                Should -Invoke Write-Warning -Times 1 -Exactly
            }

            It 'falls back to File and warns once on an invalid Mode' {
                Mock Write-Warning {}
                $config = [PSCustomObject]@{ Logging = [PSCustomObject]@{ Mode = 'Bogus' } }

                (Get-CertToolboxLoggingConfig -Config $config).Mode | Should -Be 'File'
                Get-CertToolboxLoggingConfig -Config $config | Out-Null

                Should -Invoke Write-Warning -Times 1 -Exactly
            }
        }

        Describe 'Resolve-CertToolboxLogFilePath' {
            BeforeAll {
                $script:logDir = Join-Path ([System.IO.Path]::GetTempPath()) "CertToolboxLogTest-$([guid]::NewGuid())"
            }

            AfterAll {
                Remove-Item -Path $script:logDir -Recurse -Force -ErrorAction SilentlyContinue
            }

            It 'expands the path, expands the date token, and creates the directory' {
                $file = [PSCustomObject]@{ Path = $script:logDir; FileName = 'test-{yyyyMMdd}.log' }
                $expectedName = "test-$((Get-Date).ToString('yyyyMMdd')).log"

                $result = Resolve-CertToolboxLogFilePath -File $file

                $result | Should -Be (Join-Path $script:logDir $expectedName)
                Test-Path -Path $script:logDir | Should -Be $true
            }
        }

        Describe 'Write-CertToolboxFileLogEntry' {
            BeforeAll {
                $script:logFile = Join-Path ([System.IO.Path]::GetTempPath()) "CertToolboxFileLogTest-$([guid]::NewGuid()).log"
            }

            AfterAll {
                Remove-Item -Path $script:logFile -Force -ErrorAction SilentlyContinue
            }

            It 'appends a formatted line containing level, user, cmdlet, target, and message' {
                Mock Resolve-CertToolboxLogFilePath { $script:logFile }

                $entry = [PSCustomObject]@{
                    Timestamp  = Get-Date
                    Level      = 'Information'
                    UserName   = 'alice'
                    CmdletName = 'Get-CertToolboxTlsCertificate'
                    Target     = 'www.example.com:443'
                    Message    = 'Handshake completed'
                }

                Write-CertToolboxFileLogEntry -File ([PSCustomObject]@{ Path = 'unused'; FileName = 'unused' }) -Entry $entry

                $content = Get-Content -Path $script:logFile -Raw
                $content | Should -BeLike '*[INFORMATION]*'
                $content | Should -BeLike '*alice*'
                $content | Should -BeLike '*Get-CertToolboxTlsCertificate*'
                $content | Should -BeLike '*Target=www.example.com:443*'
                $content | Should -BeLike '*Handshake completed*'
            }

            It 'never throws and warns once when the log file cannot be written' {
                Mock Resolve-CertToolboxLogFilePath { throw 'access denied' }
                Mock Write-Warning {}

                $entry = [PSCustomObject]@{ Timestamp = Get-Date; Level = 'Information'; UserName = 'alice'; CmdletName = 'Test'; Target = $null; Message = 'msg' }
                $file = [PSCustomObject]@{ Path = 'unused'; FileName = 'unused' }

                { Write-CertToolboxFileLogEntry -File $file -Entry $entry } | Should -Not -Throw
                Write-CertToolboxFileLogEntry -File $file -Entry $entry

                Should -Invoke Write-Warning -Times 1 -Exactly
            }
        }

        Describe 'Test-CertToolboxEventSourceExists' {
            It 'returns a boolean, or is skipped when this session cannot query the event logs' {
                # [System.Diagnostics.EventLog]::SourceExists() searches every local log and
                # throws (rather than returning $false) when one of them - typically "Security" -
                # is inaccessible to a non-elevated session, and is not supported at all outside
                # Windows. Both are environment limitations, not defects in this thin wrapper.
                try {
                    $result = Test-CertToolboxEventSourceExists -Source 'Posh-CertToolbox-Nonexistent-Test-Source'
                    $result | Should -BeOfType [bool]
                } catch {
                    if ($_.Exception.Message -like '*Inaccessible logs*' -or
                        (Resolve-CertToolboxException -Exception $_.Exception) -is [System.PlatformNotSupportedException]) {
                        Set-ItResult -Skipped -Because 'SourceExists() needs Windows and an elevated session to search all local event logs'
                    } else {
                        throw
                    }
                }
            }
        }

        Describe 'Write-CertToolboxEventLogEntry' {
            BeforeAll {
                # Write-EventLog and New-EventLog do not exist under PowerShell 7 or outside
                # Windows; Pester can only mock a command that exists, so stand-ins are defined
                # for the tests that exercise the "cmdlets available" branch.
                if (-not (Get-Command -Name 'Write-EventLog' -ErrorAction SilentlyContinue)) {
                    function Write-EventLog {
                        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Test stand-in, only defined where the real cmdlet does not exist.')]
                        param($LogName, $Source, $EntryType, $EventId, $Message)
                        $null = $LogName, $Source, $EntryType, $EventId, $Message
                    }
                    function New-EventLog {
                        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Test stand-in, only defined where the real cmdlet does not exist.')]
                        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test stand-in that does nothing.')]
                        param($LogName, $Source)
                        $null = $LogName, $Source
                    }
                }

                $script:eventLog = [PSCustomObject]@{ LogName = 'Application'; Source = 'Posh-CertToolbox'; EventIdInformation = 1000; EventIdWarning = 2000; EventIdError = 3000 }
            }

            It 'warns once and no-ops when Write-EventLog is unavailable on this platform' {
                Mock Get-Command { $null } -ParameterFilter { $Name -eq 'Write-EventLog' }
                Mock Write-Warning {}
                Mock New-EventLog {}

                $entry = [PSCustomObject]@{ Timestamp = Get-Date; Level = 'Information'; UserName = 'alice'; CmdletName = 'Test'; Target = $null; Message = 'msg' }

                { Write-CertToolboxEventLogEntry -EventLog $script:eventLog -Entry $entry } | Should -Not -Throw
                Write-CertToolboxEventLogEntry -EventLog $script:eventLog -Entry $entry

                Should -Invoke Write-Warning -Times 1 -Exactly
                Should -Invoke New-EventLog -Times 0 -Exactly
            }

            It 'creates the event source when missing, then writes the entry' {
                Mock Test-CertToolboxEventSourceExists { $false }
                Mock New-EventLog {}
                Mock Write-EventLog {}

                $entry = [PSCustomObject]@{ Timestamp = Get-Date; Level = 'Error'; UserName = 'alice'; CmdletName = 'Test'; Target = 'www.example.com:443'; Message = 'boom' }

                Write-CertToolboxEventLogEntry -EventLog $script:eventLog -Entry $entry

                Should -Invoke New-EventLog -Times 1 -Exactly
                Should -Invoke Write-EventLog -Times 1 -Exactly -ParameterFilter {
                    $EventId -eq 3000 -and "$EntryType" -eq 'Error' -and $Message -like '*Target=www.example.com:443*boom*'
                }
            }

            It 'writes a Debug entry as Information with a [DEBUG] prefix' {
                Mock Test-CertToolboxEventSourceExists { $true }
                Mock Write-EventLog {}

                $entry = [PSCustomObject]@{ Timestamp = Get-Date; Level = 'Debug'; UserName = 'alice'; CmdletName = 'Test'; Target = $null; Message = 'details' }

                Write-CertToolboxEventLogEntry -EventLog $script:eventLog -Entry $entry

                Should -Invoke Write-EventLog -Times 1 -Exactly -ParameterFilter {
                    $EventId -eq 1000 -and "$EntryType" -eq 'Information' -and $Message -like '`[DEBUG`] *'
                }
            }

            It 'never throws when the underlying Event Log call fails' {
                Mock Test-CertToolboxEventSourceExists { $true }
                Mock Write-EventLog { throw 'access denied' }
                Mock Write-Warning {}

                $entry = [PSCustomObject]@{ Timestamp = Get-Date; Level = 'Information'; UserName = 'alice'; CmdletName = 'Test'; Target = $null; Message = 'msg' }

                { Write-CertToolboxEventLogEntry -EventLog $script:eventLog -Entry $entry } | Should -Not -Throw
                Should -Invoke Write-Warning -Times 1 -Exactly
            }
        }

        Describe 'Write-CertToolboxLog' {
            It 'no-ops when logging is disabled' {
                Mock Get-CertToolboxLoggingConfig { [PSCustomObject]@{ Enabled = $false; MinimumLevel = 'Debug'; Mode = 'File'; File = $null; EventLog = $null } }
                Mock Write-CertToolboxFileLogEntry {}
                Mock Write-CertToolboxEventLogEntry {}

                Write-CertToolboxLog -Config ([PSCustomObject]@{}) -Level Information -Message 'msg' -CmdletName 'Test'

                Should -Invoke Write-CertToolboxFileLogEntry -Times 0 -Exactly
                Should -Invoke Write-CertToolboxEventLogEntry -Times 0 -Exactly
            }

            It 'filters out entries below MinimumLevel' {
                Mock Get-CertToolboxLoggingConfig { [PSCustomObject]@{ Enabled = $true; MinimumLevel = 'Warning'; Mode = 'File'; File = [PSCustomObject]@{}; EventLog = [PSCustomObject]@{} } }
                Mock Write-CertToolboxFileLogEntry {}

                Write-CertToolboxLog -Config ([PSCustomObject]@{}) -Level Information -Message 'msg' -CmdletName 'Test'
                Should -Invoke Write-CertToolboxFileLogEntry -Times 0 -Exactly

                Write-CertToolboxLog -Config ([PSCustomObject]@{}) -Level Error -Message 'msg' -CmdletName 'Test'
                Should -Invoke Write-CertToolboxFileLogEntry -Times 1 -Exactly
            }

            It 'dispatches to the File sink when Mode is File' {
                Mock Get-CertToolboxLoggingConfig { [PSCustomObject]@{ Enabled = $true; MinimumLevel = 'Debug'; Mode = 'File'; File = [PSCustomObject]@{}; EventLog = [PSCustomObject]@{} } }
                Mock Write-CertToolboxFileLogEntry {}
                Mock Write-CertToolboxEventLogEntry {}

                Write-CertToolboxLog -Config ([PSCustomObject]@{}) -Level Information -Message 'msg' -CmdletName 'Test'

                Should -Invoke Write-CertToolboxFileLogEntry -Times 1 -Exactly
                Should -Invoke Write-CertToolboxEventLogEntry -Times 0 -Exactly
            }

            It 'dispatches to the EventLog sink when Mode is EventLog' {
                Mock Get-CertToolboxLoggingConfig { [PSCustomObject]@{ Enabled = $true; MinimumLevel = 'Debug'; Mode = 'EventLog'; File = [PSCustomObject]@{}; EventLog = [PSCustomObject]@{} } }
                Mock Write-CertToolboxFileLogEntry {}
                Mock Write-CertToolboxEventLogEntry {}

                Write-CertToolboxLog -Config ([PSCustomObject]@{}) -Level Information -Message 'msg' -CmdletName 'Test'

                Should -Invoke Write-CertToolboxEventLogEntry -Times 1 -Exactly
                Should -Invoke Write-CertToolboxFileLogEntry -Times 0 -Exactly
            }

            It 'redacts Password/Secret/Token/Credential/APIKey-named bound parameters but keeps others' {
                Mock Get-CertToolboxLoggingConfig { [PSCustomObject]@{ Enabled = $true; MinimumLevel = 'Debug'; Mode = 'File'; File = [PSCustomObject]@{}; EventLog = [PSCustomObject]@{} } }
                $script:capturedEntry = $null
                Mock Write-CertToolboxFileLogEntry { $script:capturedEntry = $Entry }

                Write-CertToolboxLog -Config ([PSCustomObject]@{}) -Level Debug -Message 'Cmdlet invoked' -CmdletName 'Test' `
                    -BoundParameters @{ ClientCertificatePassword = 'super-secret-value'; HostName = @('a.example', 'b.example'); Port = 8443 }

                $script:capturedEntry.Message | Should -Not -BeLike '*super-secret-value*'
                $script:capturedEntry.Message | Should -BeLike '*ClientCertificatePassword=<redacted>*'
                $script:capturedEntry.Message | Should -BeLike '*HostName=a.example,b.example*'
                $script:capturedEntry.Message | Should -BeLike '*Port=8443*'
            }

            It 'stamps UserName from [System.Environment]::UserName and carries the target' {
                Mock Get-CertToolboxLoggingConfig { [PSCustomObject]@{ Enabled = $true; MinimumLevel = 'Debug'; Mode = 'File'; File = [PSCustomObject]@{}; EventLog = [PSCustomObject]@{} } }
                $script:capturedEntry = $null
                Mock Write-CertToolboxFileLogEntry { $script:capturedEntry = $Entry }

                Write-CertToolboxLog -Config ([PSCustomObject]@{}) -Level Information -Message 'msg' -CmdletName 'Test' -Target 'www.example.com:443'

                $script:capturedEntry.UserName | Should -Be ([System.Environment]::UserName)
                $script:capturedEntry.Target | Should -Be 'www.example.com:443'
            }

            It 'never throws even when the logging config itself is broken' {
                Mock Get-CertToolboxLoggingConfig { throw 'config is corrupt' }
                Mock Write-Warning {}

                { Write-CertToolboxLog -Config ([PSCustomObject]@{}) -Level Information -Message 'msg' -CmdletName 'Test' } | Should -Not -Throw
                Should -Invoke Write-Warning -Times 1 -Exactly
            }
        }

        # No mocks below the config path: a real config file, a real cmdlet call through the
        # real logging layer, and the real log file read back.
        Describe 'End to end: a public cmdlet writes to a real log file' {
            BeforeAll {
                $script:workDir = Join-Path ([System.IO.Path]::GetTempPath()) "CertToolboxLogE2E-$([guid]::NewGuid())"
                New-Item -ItemType Directory -Path $script:workDir -Force | Out-Null
                $script:configFile = Join-Path $script:workDir 'config.json'
                $script:logDir = Join-Path $script:workDir 'logs'

                [PSCustomObject]@{
                    version = '1.0'
                    Logging = [PSCustomObject]@{
                        Enabled      = $true
                        MinimumLevel = 'Debug'
                        Mode         = 'File'
                        File         = [PSCustomObject]@{ Path = $script:logDir; FileName = 'e2e.log' }
                    }
                } | ConvertTo-Json -Depth 5 | Set-Content -Path $script:configFile -Encoding UTF8
            }

            AfterAll {
                Remove-Item -Path $script:workDir -Recurse -Force -ErrorAction SilentlyContinue
            }

            It 'logs the invocation, the result and a failure, each on its own line' {
                Mock Get-CertToolboxConfigPath { $script:configFile }
                Mock Find-CertToolboxCaaRecordSet {
                    [PSCustomObject]@{ RecordSetName = $null; Record = @(); QueriedName = @('good.example', 'example') }
                } -ParameterFilter { $Name -eq 'good.example' }
                Mock Find-CertToolboxCaaRecordSet { throw 'DNS is down' } -ParameterFilter { $Name -eq 'bad.example' }

                Get-CertToolboxCaaRecord -Name 'good.example', 'bad.example' -ErrorAction SilentlyContinue | Out-Null

                $lines = @(Get-Content -Path (Join-Path $script:logDir 'e2e.log'))
                $lines.Count | Should -Be 3
                $lines[0] | Should -BeLike '*`[DEBUG`]*`[Get-CertToolboxCaaRecord`] Cmdlet invoked (*Name=good.example,bad.example*'
                $lines[1] | Should -BeLike '*`[INFORMATION`]*Target=good.example`] No CAA record set found*'
                $lines[2] | Should -BeLike '*`[ERROR`]*Target=bad.example`] CAA lookup failed: DNS is down*'
            }
        }
    }
}

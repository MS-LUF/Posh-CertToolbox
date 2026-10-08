BeforeDiscovery {
    Import-Module (Join-Path $PSScriptRoot '../../Posh-CertToolbox.psd1') -Force
}

Describe 'Private/Config' -Tag Unit {
    InModuleScope 'Posh-CertToolbox' {
        BeforeEach {
            $script:LoggingConfigWarned = $false
        }

        Describe 'Get-CertToolboxConfigPath' {
            It 'returns a path under the user profile ending in Posh-CertToolbox-Config.json' {
                $path = Get-CertToolboxConfigPath
                $path | Should -BeLike "$home*Posh-CertToolbox*"
                $path | Should -BeLike '*Posh-CertToolbox-Config.json'
            }
        }

        Describe 'Read-CertToolboxConfigFile' {
            BeforeAll {
                $script:fixturePath = Join-Path ([System.IO.Path]::GetTempPath()) "CertToolboxConfigTest-$([guid]::NewGuid()).json"
                $script:brokenPath = Join-Path ([System.IO.Path]::GetTempPath()) "CertToolboxConfigTest-$([guid]::NewGuid())-broken.json"
                $script:missingPath = Join-Path ([System.IO.Path]::GetTempPath()) "CertToolboxConfigTest-$([guid]::NewGuid())-missing.json"

                '{ "version": "1.0", "Logging": { "Enabled": true, "MinimumLevel": "Debug" } }' |
                    Set-Content -Path $script:fixturePath -Encoding UTF8
                '{ "version": "1.0", "Logging": { ' | Set-Content -Path $script:brokenPath -Encoding UTF8
            }

            AfterAll {
                Remove-Item -Path $script:fixturePath, $script:brokenPath -Force -ErrorAction SilentlyContinue
            }

            It 'returns a default object with no Logging section when the file does not exist' {
                $result = Read-CertToolboxConfigFile -Path $script:missingPath
                $result.version | Should -Be '1.0'
                $result.Logging | Should -BeNullOrEmpty
            }

            It 'parses an existing JSON file' {
                $result = Read-CertToolboxConfigFile -Path $script:fixturePath
                $result.Logging.Enabled | Should -BeTrue
                $result.Logging.MinimumLevel | Should -Be 'Debug'
            }

            It 'reads the file again on every call' {
                (Read-CertToolboxConfigFile -Path $script:fixturePath).Logging.MinimumLevel | Should -Be 'Debug'
                '{ "version": "1.0", "Logging": { "Enabled": true, "MinimumLevel": "Error" } }' |
                    Set-Content -Path $script:fixturePath -Encoding UTF8
                (Read-CertToolboxConfigFile -Path $script:fixturePath).Logging.MinimumLevel | Should -Be 'Error'
            }

            It 'returns the default and warns once, without throwing, when the file is not valid JSON' {
                Mock Write-Warning {}

                $result = Read-CertToolboxConfigFile -Path $script:brokenPath
                Read-CertToolboxConfigFile -Path $script:brokenPath | Out-Null

                $result.version | Should -Be '1.0'
                $result.Logging | Should -BeNullOrEmpty
                Should -Invoke Write-Warning -Times 1 -Exactly
            }
        }

        Describe 'Sample configuration file' {
            It 'is valid JSON that normalizes to logging disabled with the module defaults' {
                $samplePath = Join-Path $script:ModuleRoot 'Config/Posh-CertToolbox.sample.json'
                $logging = Get-CertToolboxLoggingConfig -Config (Read-CertToolboxConfigFile -Path $samplePath)

                $logging.Enabled | Should -BeFalse
                $logging.MinimumLevel | Should -Be 'Information'
                $logging.Mode | Should -Be 'File'
                $logging.File.FileName | Should -Be 'Posh-CertToolbox-{yyyyMMdd}.log'
                $logging.EventLog.Source | Should -Be 'Posh-CertToolbox'
            }
        }
    }
}

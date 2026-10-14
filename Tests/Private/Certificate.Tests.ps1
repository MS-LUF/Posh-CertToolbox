BeforeDiscovery {
    Import-Module (Join-Path $PSScriptRoot '../../Posh-CertToolbox.psd1') -Force
}

Describe 'Private/Certificate' -Tag Unit {
    InModuleScope 'Posh-CertToolbox' {
        BeforeAll {
            . (Join-Path $PSScriptRoot '../TestHelper.ps1')
            $script:chain = Get-TestCertificateChain
        }

        Describe 'Read-CertToolboxDerHeader' {
            It 'reads a short-form length' {
                $header = Read-CertToolboxDerHeader -Bytes ([byte[]](0x30, 0x03, 1, 2, 3)) -Offset 0
                $header.Tag | Should -Be 0x30
                $header.Length | Should -Be 3
                $header.ValueOffset | Should -Be 2
            }

            It 'reads a long-form length' {
                $bytes = [byte[]](@(0x30, 0x82, 0x01, 0x02) + (1..258 | ForEach-Object { 0 }))
                $header = Read-CertToolboxDerHeader -Bytes $bytes -Offset 0
                $header.Length | Should -Be 258
                $header.ValueOffset | Should -Be 4
            }

            It 'returns nothing when the header runs past the end of the data' {
                Read-CertToolboxDerHeader -Bytes ([byte[]](0x30)) -Offset 0 | Should -BeNullOrEmpty
                Read-CertToolboxDerHeader -Bytes ([byte[]](0x30, 0x82, 0x01)) -Offset 0 | Should -BeNullOrEmpty
            }
        }

        Describe 'Get-CertToolboxPublicKeySize' {
            It 'returns the modulus size of an RSA key' {
                Get-CertToolboxPublicKeySize -Certificate $script:chain.Leaf | Should -Be 2048

                $key = [System.Security.Cryptography.RSA]::Create(3072)
                $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                    'CN=rsa3072', $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
                $certificate = $request.CreateSelfSigned([System.DateTimeOffset]::UtcNow.AddDays(-1), [System.DateTimeOffset]::UtcNow.AddDays(1))
                Get-CertToolboxPublicKeySize -Certificate $certificate | Should -Be 3072
            }

            It 'returns the curve size of an elliptic curve key (<Curve>)' -ForEach @(
                @{ Curve = 'nistP256'; Expected = 256 }
                @{ Curve = 'nistP384'; Expected = 384 }
                @{ Curve = 'nistP521'; Expected = 521 }
            ) {
                $key = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::$Curve)
                $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                    "CN=$Curve", $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
                $certificate = $request.CreateSelfSigned([System.DateTimeOffset]::UtcNow.AddDays(-1), [System.DateTimeOffset]::UtcNow.AddDays(1))

                Get-CertToolboxPublicKeySize -Certificate $certificate | Should -Be $Expected
            }
        }

        Describe 'Test-CertToolboxSelfSigned' {
            It 'is true for a self-signed root' {
                Test-CertToolboxSelfSigned -Certificate $script:chain.Root | Should -BeTrue
            }

            It 'is false for certificates issued by another one' {
                Test-CertToolboxSelfSigned -Certificate $script:chain.Intermediate | Should -BeFalse
                Test-CertToolboxSelfSigned -Certificate $script:chain.Leaf | Should -BeFalse
            }
        }

        Describe 'Get-CertToolboxSubjectAlternativeName' {
            It 'returns DNS names and IP addresses in order' {
                $names = @(Get-CertToolboxSubjectAlternativeName -Certificate $script:chain.Leaf)
                ($names -join ',') | Should -Be 'test.example,*.test.example,192.0.2.10'
            }

            It 'returns nothing for a certificate without the extension' {
                Get-CertToolboxSubjectAlternativeName -Certificate $script:chain.Other | Should -BeNullOrEmpty
            }
        }

        Describe 'ConvertTo-CertToolboxCertificateInfo' {
            It 'describes a leaf certificate' {
                $info = ConvertTo-CertToolboxCertificateInfo -Certificate $script:chain.Leaf

                $info.PSObject.TypeNames[0] | Should -Be 'CertToolbox.CertificateInfo'
                $info.Subject | Should -Be 'CN=test.example'
                $info.Issuer | Should -Be 'CN=CertToolbox Test Intermediate'
                $info.Thumbprint | Should -Be $script:chain.Leaf.Thumbprint
                $info.PublicKeySize | Should -Be 2048
                $info.IsSelfSigned | Should -BeFalse
                $info.IsCertificateAuthority | Should -BeFalse
                $info.DaysUntilExpiry | Should -BeIn 29, 30
                ($info.SubjectAlternativeName -join ',') | Should -Be 'test.example,*.test.example,192.0.2.10'
                $info.Certificate | Should -Be $script:chain.Leaf
                $info.PSObject.Properties['Status'] | Should -BeNullOrEmpty
            }

            It 'flags a CA certificate and a self-signed one' {
                $info = ConvertTo-CertToolboxCertificateInfo -Certificate $script:chain.Root
                $info.IsCertificateAuthority | Should -BeTrue
                $info.IsSelfSigned | Should -BeTrue
                $info.SubjectAlternativeName | Should -BeNullOrEmpty
            }

            It 'adds a Status property only when -Status is used, including an empty one' {
                $withStatus = ConvertTo-CertToolboxCertificateInfo -Certificate $script:chain.Leaf -Status 'NotTimeValid', 'Revoked'
                ($withStatus.Status -join ',') | Should -Be 'NotTimeValid,Revoked'

                $empty = ConvertTo-CertToolboxCertificateInfo -Certificate $script:chain.Leaf -Status @()
                $empty.PSObject.Properties['Status'] | Should -Not -BeNullOrEmpty
                $empty.Status | Should -BeNullOrEmpty
            }
        }

        Describe 'Get-CertToolboxChainDiagnostic' {
            It 'reports nothing when the server sent every intermediate' {
                $result = Get-CertToolboxChainDiagnostic `
                    -ServerCertificate $script:chain.Leaf, $script:chain.Intermediate `
                    -LocalCertificate $script:chain.Leaf, $script:chain.Intermediate, $script:chain.Root

                $result.MissingIntermediate | Should -BeNullOrEmpty
                $result.ServerSentRoot | Should -BeFalse
                $result.UnusedServerCertificate | Should -BeNullOrEmpty
            }

            It 'reports an intermediate the server did not send, but not the root' {
                $result = Get-CertToolboxChainDiagnostic `
                    -ServerCertificate $script:chain.Leaf `
                    -LocalCertificate $script:chain.Leaf, $script:chain.Intermediate, $script:chain.Root

                @($result.MissingIntermediate).Count | Should -Be 1
                $result.MissingIntermediate[0].Thumbprint | Should -Be $script:chain.Intermediate.Thumbprint
            }

            It 'reports a root sent by the server' {
                $result = Get-CertToolboxChainDiagnostic `
                    -ServerCertificate $script:chain.Leaf, $script:chain.Intermediate, $script:chain.Root `
                    -LocalCertificate $script:chain.Leaf, $script:chain.Intermediate, $script:chain.Root

                $result.ServerSentRoot | Should -BeTrue
                $result.UnusedServerCertificate | Should -BeNullOrEmpty
            }

            It 'does not call a self-signed leaf a root sent by the server' {
                $result = Get-CertToolboxChainDiagnostic -ServerCertificate $script:chain.Other -LocalCertificate $script:chain.Other

                $result.ServerSentRoot | Should -BeFalse
                $result.MissingIntermediate | Should -BeNullOrEmpty
            }

            It 'reports a server certificate the local chain did not use' {
                $result = Get-CertToolboxChainDiagnostic `
                    -ServerCertificate $script:chain.Leaf, $script:chain.Intermediate, $script:chain.Other `
                    -LocalCertificate $script:chain.Leaf, $script:chain.Intermediate, $script:chain.Root

                @($result.UnusedServerCertificate).Count | Should -Be 1
                $result.UnusedServerCertificate[0].Thumbprint | Should -Be $script:chain.Other.Thumbprint
            }

            It 'accepts empty chains' {
                $result = Get-CertToolboxChainDiagnostic -ServerCertificate @() -LocalCertificate @()

                $result.MissingIntermediate | Should -BeNullOrEmpty
                $result.ServerSentRoot | Should -BeFalse
                $result.UnusedServerCertificate | Should -BeNullOrEmpty
            }
        }
    }
}

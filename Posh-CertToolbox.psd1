@{
    RootModule        = 'Posh-CertToolbox.psm1'
    ModuleVersion     = '0.4.0'
    GUID              = 'b7e4c1a2-5f3d-4e8a-9c6b-2d1f0a7e8c34'
    Author            = 'MS-LUF'
    CompanyName       = 'lucas-cueff.com'
    Copyright         = '(c) 2026 lucas-cueff.com Distributed under Artistic Licence 2.0 (https://opensource.org/licenses/artistic-license-2.0).'
    Description       = 'Troubleshoot TLS and certificates: inspect an endpoint and its certificate chain, probe TLS versions, read DNS CAA records.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Get-CertToolboxCaaRecord',
        'Get-CertToolboxTlsCertificate',
        'Test-CertToolboxTlsProtocol'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    FileList          = @('Posh-CertToolbox.psm1')
    PrivateData       = @{
        PSData = @{
            Tags         = @('TLS', 'SSL', 'X509', 'Certificate', 'CAA', 'DNS', 'Security', 'Troubleshooting')
            LicenseUri   = 'https://opensource.org/licenses/artistic-license-2.0'
            ReleaseNotes = 'v0.4.0 - README, HowTo and generated help files. See the change log in README.md.'
        }
    }
}

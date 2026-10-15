@{
    RootModule        = 'Posh-CertToolbox.psm1'
    ModuleVersion     = '0.9.1'
    GUID              = 'b7e4c1a2-5f3d-4e8a-9c6b-2d1f0a7e8c34'
    Author            = 'MS-LUF'
    CompanyName       = 'lucas-cueff.com'
    Copyright         = '(c) 2026 lucas-cueff.com Distributed under Artistic Licence 2.0 (https://opensource.org/licenses/artistic-license-2.0).'
    Description       = 'Troubleshoot TLS and certificates: inspect an endpoint and its certificate chain, scan the versions and cipher suites a server supports, read DNS CAA records.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Get-CertToolboxCaaRecord',
        'Get-CertToolboxTlsCapability',
        'Get-CertToolboxTlsCertificate',
        'Test-CertToolboxTlsProtocol'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    FormatsToProcess  = @('Posh-CertToolbox.format.ps1xml')
    FileList          = @('Posh-CertToolbox.psm1', 'Posh-CertToolbox.format.ps1xml')
    PrivateData       = @{
        PSData = @{
            Tags         = @('TLS', 'SSL', 'X509', 'Certificate', 'CAA', 'DNS', 'Security', 'Troubleshooting')
            LicenseUri   = 'https://opensource.org/licenses/artistic-license-2.0'
            ReleaseNotes = 'v0.9.1 - Fix: on macOS, ServerChain is now what the server sent. See the change log in README.md.'
        }
    }
}

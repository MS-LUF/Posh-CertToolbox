function Get-CertToolboxConfigPath {
    <#
    .SYNOPSIS
        Resolves the full path to the live Posh-CertToolbox configuration file.
    .DESCRIPTION
        Always $home\Posh-CertToolbox\Posh-CertToolbox-Config.json - the user-profile location,
        not the module root, so the live config survives an AllUsers-scope module install or
        upgrade, and resolves consistently under Windows PowerShell 5.1 and PowerShell 7 on
        Windows, Linux or macOS ($home is an automatic variable under all of them).
    .OUTPUTS
        String.
    .EXAMPLE
        Get-CertToolboxConfigPath
        Returns e.g. 'C:\Users\alice\Posh-CertToolbox\Posh-CertToolbox-Config.json' on Windows,
        or '/home/alice/Posh-CertToolbox/Posh-CertToolbox-Config.json' on Linux.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $configDirectory = Join-Path -Path $home -ChildPath 'Posh-CertToolbox'
    Join-Path -Path $configDirectory -ChildPath 'Posh-CertToolbox-Config.json'
}

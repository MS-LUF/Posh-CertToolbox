function Get-CertToolboxPlatform {
    <#
    .SYNOPSIS
        Tells which operating system the module runs on: Windows, Linux or MacOS.
    .DESCRIPTION
        Windows PowerShell 5.1 has no IsLinux or IsMacOS variable and only runs on Windows, so
        their absence means Windows.

        Kept in its own function so that the code depending on the platform can be tested for
        every platform from any machine.
    .OUTPUTS
        System.String. Windows, Linux or MacOS.
    .EXAMPLE
        Get-CertToolboxPlatform
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $isMac = Get-Variable -Name 'IsMacOS' -ValueOnly -ErrorAction SilentlyContinue
    $isLinuxHost = Get-Variable -Name 'IsLinux' -ValueOnly -ErrorAction SilentlyContinue

    if ($isMac) {
        return 'MacOS'
    }
    if ($isLinuxHost) {
        return 'Linux'
    }
    'Windows'
}

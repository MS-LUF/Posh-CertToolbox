function Test-CertToolboxEventSourceExists {
    <#
    .SYNOPSIS
        Returns whether a Windows Event Log source is already registered.
    .DESCRIPTION
        Thin wrapper around [System.Diagnostics.EventLog]::SourceExists(), extracted into its
        own function so Write-CertToolboxEventLogEntry's source-creation branch is unit testable
        with a mock instead of depending on real Windows Event Log state or elevation.
    .PARAMETER Source
        The event source name to check.
    .OUTPUTS
        Boolean.
    .EXAMPLE
        Test-CertToolboxEventSourceExists -Source 'Posh-CertToolbox'
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Exists is a verb form ending in "s", not a plural noun - PSUseSingularNouns false-positives on it.')]
    param(
        [Parameter(Mandatory)]
        [string] $Source
    )

    [System.Diagnostics.EventLog]::SourceExists($Source)
}

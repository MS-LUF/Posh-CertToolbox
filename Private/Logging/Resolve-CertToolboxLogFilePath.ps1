function Resolve-CertToolboxLogFilePath {
    <#
    .SYNOPSIS
        Resolves the full log file path from the Logging.File configuration.
    .DESCRIPTION
        Expands environment variables in the configured Path (the %VAR% syntax, which the
        runtime's ExpandEnvironmentVariables supports on every platform: %USERPROFILE% on
        Windows, %HOME% on Linux and macOS) and any {DateFormatToken} placeholders in the
        configured FileName (e.g. {yyyyMMdd}) using date format strings evaluated against the
        current date, then ensures the target directory exists.
    .PARAMETER File
        The Logging.File section (Path, FileName) as returned by Get-CertToolboxLoggingConfig.
    .OUTPUTS
        String. Full path to the log file to append to.
    .EXAMPLE
        Resolve-CertToolboxLogFilePath -File $loggingConfig.File
        Returns e.g. 'C:\Users\alice\Documents\Logs\Posh-CertToolbox-20261008.log'.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject] $File
    )

    $expandedPath = [System.Environment]::ExpandEnvironmentVariables($File.Path)

    $expandedFileName = [regex]::Replace($File.FileName, '\{([^}]+)\}', {
            param($match)
            (Get-Date).ToString($match.Groups[1].Value)
        })

    if (-not (Test-Path -Path $expandedPath)) {
        New-Item -ItemType Directory -Path $expandedPath -Force | Out-Null
    }

    Join-Path -Path $expandedPath -ChildPath $expandedFileName
}

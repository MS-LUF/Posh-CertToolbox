function Get-CertToolboxLoggingConfig {
    <#
    .SYNOPSIS
        Reads and normalizes the global Logging section of the configuration.
    .DESCRIPTION
        Returns Config.Logging with every key defaulted when absent, so callers never need to
        null-check. A config with no Logging key at all normalizes to Enabled = $false (opt-in).
        MinimumLevel and Mode are validated against their known sets; an invalid value falls
        back to the default and emits one Write-Warning per session rather than failing every
        log call.

        The default File.Path is computed via [System.IO.Path]::GetTempPath() rather than a
        literal '%TEMP%\...' string: this module must also resolve a sane default under
        PowerShell 7 on Linux and macOS, where the TEMP environment variable does not exist and
        would leave the token unexpanded.
    .PARAMETER Config
        The parsed configuration object returned by Read-CertToolboxConfigFile.
    .OUTPUTS
        PSCustomObject. Normalized Logging configuration (Enabled, MinimumLevel, Mode, File, EventLog).
    .EXAMPLE
        Get-CertToolboxLoggingConfig -Config (Read-CertToolboxConfigFile)
        Returns the normalized Logging configuration, defaulted if absent.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject] $Config
    )

    $logging = $Config.Logging

    $enabled = $false
    if ($logging -and $null -ne $logging.Enabled) { $enabled = [bool]$logging.Enabled }

    $minimumLevel = 'Information'
    if ($logging -and $logging.MinimumLevel) {
        if ($script:LogLevelSeverity.ContainsKey($logging.MinimumLevel)) {
            $minimumLevel = $logging.MinimumLevel
        } elseif (-not $script:LoggingConfigWarned) {
            $script:LoggingConfigWarned = $true
            Write-Warning "Logging.MinimumLevel '$($logging.MinimumLevel)' is not one of Debug/Information/Warning/Error; using 'Information'."
        }
    }

    $mode = 'File'
    if ($logging -and $logging.Mode) {
        if ($logging.Mode -eq 'File' -or $logging.Mode -eq 'EventLog') {
            $mode = $logging.Mode
        } elseif (-not $script:LoggingConfigWarned) {
            $script:LoggingConfigWarned = $true
            Write-Warning "Logging.Mode '$($logging.Mode)' is not one of File/EventLog; using 'File'."
        }
    }

    $filePath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'Posh-CertToolbox'
    if ($logging -and $logging.File -and $logging.File.Path) { $filePath = $logging.File.Path }

    $fileName = 'Posh-CertToolbox-{yyyyMMdd}.log'
    if ($logging -and $logging.File -and $logging.File.FileName) { $fileName = $logging.File.FileName }

    $eventLogName = 'Application'
    if ($logging -and $logging.EventLog -and $logging.EventLog.LogName) { $eventLogName = $logging.EventLog.LogName }

    $eventSource = 'Posh-CertToolbox'
    if ($logging -and $logging.EventLog -and $logging.EventLog.Source) { $eventSource = $logging.EventLog.Source }

    $eventIdInformation = 1000
    if ($logging -and $logging.EventLog -and $logging.EventLog.EventIdInformation) {
        $eventIdInformation = [int]$logging.EventLog.EventIdInformation
    }

    $eventIdWarning = 2000
    if ($logging -and $logging.EventLog -and $logging.EventLog.EventIdWarning) {
        $eventIdWarning = [int]$logging.EventLog.EventIdWarning
    }

    $eventIdError = 3000
    if ($logging -and $logging.EventLog -and $logging.EventLog.EventIdError) {
        $eventIdError = [int]$logging.EventLog.EventIdError
    }

    [PSCustomObject]@{
        Enabled      = $enabled
        MinimumLevel = $minimumLevel
        Mode         = $mode
        File         = [PSCustomObject]@{
            Path     = $filePath
            FileName = $fileName
        }
        EventLog     = [PSCustomObject]@{
            LogName            = $eventLogName
            Source             = $eventSource
            EventIdInformation = $eventIdInformation
            EventIdWarning     = $eventIdWarning
            EventIdError       = $eventIdError
        }
    }
}

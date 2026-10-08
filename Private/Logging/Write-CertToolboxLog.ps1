function Write-CertToolboxLog {
    <#
    .SYNOPSIS
        Writes a log entry to the configured logging destination (file or Windows Event Log).
    .DESCRIPTION
        Central logging entry point, called by every public cmdlet. Reads and normalizes the
        Logging section of the configuration, filters by MinimumLevel, and dispatches to
        Write-CertToolboxFileLogEntry or Write-CertToolboxEventLogEntry depending on Mode.
        Every entry is stamped with the current OS user name ([System.Environment]::UserName,
        not WindowsIdentity - this module must also run on Linux and macOS).

        When -BoundParameters is supplied, its keys/values are appended to the message with
        Credential/Password/Secret/Token/APIKey-named parameters redacted, so a secret passed
        directly to a cmdlet never reaches a log file or the Windows Event Log. No cmdlet of
        this module takes such a parameter today; the rule is kept so that one added later
        (a client certificate password, for instance) is covered from the start. Callers pass
        this only on the Debug-level entry-point log of each cmdlet invocation.

        No-ops silently when logging is disabled (Logging.Enabled = $false, the default) or
        when Level is below the configured MinimumLevel. Never throws - a logging failure must
        never break the cmdlet's actual work.
    .PARAMETER Config
        The parsed configuration object returned by Read-CertToolboxConfigFile.
    .PARAMETER Level
        Severity of this entry: Debug, Information, Warning, or Error.
    .PARAMETER Message
        The log message.
    .PARAMETER CmdletName
        Name of the calling cmdlet, e.g. $MyInvocation.MyCommand.Name.
    .PARAMETER Target
        Optional. What the action was about: an endpoint as host:port, or a DNS name.
    .PARAMETER BoundParameters
        Optional. $PSBoundParameters of the calling cmdlet; appended to the message with
        sensitive values redacted.
    .EXAMPLE
        Write-CertToolboxLog -Config $config -Level Debug -CmdletName $MyInvocation.MyCommand.Name -Message 'Cmdlet invoked' -BoundParameters $PSBoundParameters
        Logs cmdlet entry with its bound parameters (secrets redacted) at Debug level.
    .EXAMPLE
        Write-CertToolboxLog -Config $config -Level Information -CmdletName 'Get-CertToolboxTlsCertificate' -Target 'www.example.com:443' -Message 'Handshake completed'
        Logs a one-line summary of a successful operation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject] $Config,

        [Parameter(Mandatory)]
        [ValidateSet('Debug', 'Information', 'Warning', 'Error')]
        [string] $Level,

        [Parameter(Mandatory)]
        [string] $Message,

        [Parameter(Mandatory)]
        [string] $CmdletName,

        [Parameter()]
        [string] $Target,

        [Parameter()]
        [System.Collections.IDictionary] $BoundParameters
    )

    try {
        $loggingConfig = Get-CertToolboxLoggingConfig -Config $Config
        if (-not $loggingConfig.Enabled) { return }

        $minimumSeverity = $script:LogLevelSeverity[$loggingConfig.MinimumLevel]
        $entrySeverity = $script:LogLevelSeverity[$Level]
        if ($entrySeverity -lt $minimumSeverity) { return }

        $fullMessage = $Message
        if ($BoundParameters -and $BoundParameters.Count -gt 0) {
            $redacted = foreach ($key in ($BoundParameters.Keys | Sort-Object)) {
                if ($key -match 'Credential|Password|Secret|Token|APIKey') {
                    "$key=<redacted>"
                } else {
                    "$key=$($BoundParameters[$key] -join ',')"
                }
            }
            $fullMessage = "$Message ($($redacted -join '; '))"
        }

        $entry = [PSCustomObject]@{
            Timestamp  = Get-Date
            Level      = $Level
            UserName   = [System.Environment]::UserName
            CmdletName = $CmdletName
            Target     = $Target
            Message    = $fullMessage
        }

        if ($loggingConfig.Mode -eq 'EventLog') {
            Write-CertToolboxEventLogEntry -EventLog $loggingConfig.EventLog -Entry $entry
        } else {
            Write-CertToolboxFileLogEntry -File $loggingConfig.File -Entry $entry
        }
    } catch {
        if (-not $script:LoggingSinkFailed) {
            $script:LoggingSinkFailed = $true
            Write-Warning "Posh-CertToolbox logging failed and will be skipped for the rest of this session: $_"
        }
    }
}

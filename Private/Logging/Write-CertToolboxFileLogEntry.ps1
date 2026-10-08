function Write-CertToolboxFileLogEntry {
    <#
    .SYNOPSIS
        Appends one formatted log line to the configured log file.
    .DESCRIPTION
        Resolves the log file path from the Logging.File configuration and appends a single
        line. Never throws: a failure (bad path, permissions, locked file) is surfaced once
        per session via Write-Warning and silently skipped afterwards, so a broken logging
        destination never interrupts the calling cmdlet's actual work.
    .PARAMETER File
        The Logging.File section (Path, FileName) as returned by Get-CertToolboxLoggingConfig.
    .PARAMETER Entry
        The log entry object (Timestamp, Level, UserName, CmdletName, Target, Message) as built
        by Write-CertToolboxLog.
    .EXAMPLE
        Write-CertToolboxFileLogEntry -File $loggingConfig.File -Entry $entry
        Appends $entry to the resolved log file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject] $File,

        [Parameter(Mandatory)]
        [PSCustomObject] $Entry
    )

    try {
        $logPath = Resolve-CertToolboxLogFilePath -File $File

        $context = $Entry.CmdletName
        if ($Entry.Target) { $context += " Target=$($Entry.Target)" }

        $line = '{0:yyyy-MM-dd HH:mm:ss.fff} [{1}] [{2}] [{3}] {4}' -f `
            $Entry.Timestamp, $Entry.Level.ToUpper(), $Entry.UserName, $context, $Entry.Message

        Add-Content -Path $logPath -Value $line -Encoding UTF8 -ErrorAction Stop
    } catch {
        if (-not $script:LoggingSinkFailed) {
            $script:LoggingSinkFailed = $true
            Write-Warning "Posh-CertToolbox file logging failed and will be skipped for the rest of this session: $_"
        }
    }
}

function Write-CertToolboxEventLogEntry {
    <#
    .SYNOPSIS
        Writes one entry to the configured Windows Event Log, creating the source if needed.
    .DESCRIPTION
        Ensures the configured event source exists (registering it under the configured log
        name via New-EventLog if not - this requires an elevated session the first time), then
        writes the entry with the EventId/EntryType matching its level. Debug-level entries are
        written as Information entries (there is no dedicated Debug event ID or entry type in
        Windows Event Log) with the message prefixed [DEBUG].

        PowerShell 7 does not ship the Windows Event Log cmdlets, and this module must run on
        Linux and macOS where there is no Windows Event Log at all - checked via Get-Command
        before any Event Log call; if absent, warns once per session and every subsequent call
        silently no-ops rather than throwing a hard error.

        Never throws: a failure (source creation denied, log unreachable, cmdlets unavailable)
        is surfaced once per session via Write-Warning and that entry is skipped, so a broken
        logging destination never interrupts the calling cmdlet's actual work.
    .PARAMETER EventLog
        The Logging.EventLog section as returned by Get-CertToolboxLoggingConfig.
    .PARAMETER Entry
        The log entry object (Timestamp, Level, UserName, CmdletName, Target, Message) as built
        by Write-CertToolboxLog.
    .EXAMPLE
        Write-CertToolboxEventLogEntry -EventLog $loggingConfig.EventLog -Entry $entry
        Writes $entry to the configured Windows Event Log.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject] $EventLog,

        [Parameter(Mandatory)]
        [PSCustomObject] $Entry
    )

    if (-not (Get-Command -Name 'Write-EventLog' -ErrorAction SilentlyContinue)) {
        if (-not $script:LoggingSinkFailed) {
            $script:LoggingSinkFailed = $true
            Write-Warning 'Posh-CertToolbox event log logging is unavailable on this platform (Write-EventLog not found) and will be skipped for the rest of this session.'
        }
        return
    }

    try {
        if (-not (Test-CertToolboxEventSourceExists -Source $EventLog.Source)) {
            New-EventLog -LogName $EventLog.LogName -Source $EventLog.Source
        }

        $entryType = [System.Diagnostics.EventLogEntryType]::Information
        $eventId = $EventLog.EventIdInformation
        if ($Entry.Level -eq 'Warning') {
            $entryType = [System.Diagnostics.EventLogEntryType]::Warning
            $eventId = $EventLog.EventIdWarning
        } elseif ($Entry.Level -eq 'Error') {
            $entryType = [System.Diagnostics.EventLogEntryType]::Error
            $eventId = $EventLog.EventIdError
        }

        $context = $Entry.CmdletName
        if ($Entry.Target) { $context += " Target=$($Entry.Target)" }

        $prefix = ''
        if ($Entry.Level -eq 'Debug') { $prefix = '[DEBUG] ' }
        $message = "$prefix[$($Entry.UserName)] [$context] $($Entry.Message)"

        Write-EventLog -LogName $EventLog.LogName -Source $EventLog.Source `
            -EntryType $entryType -EventId $eventId -Message $message
    } catch {
        if (-not $script:LoggingSinkFailed) {
            $script:LoggingSinkFailed = $true
            Write-Warning "Posh-CertToolbox event log logging failed and will be skipped for the rest of this session: $_"
        }
    }
}

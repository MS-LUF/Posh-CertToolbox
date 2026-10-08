function Read-CertToolboxConfigFile {
    <#
    .SYNOPSIS
        Reads and parses the Posh-CertToolbox configuration file.
    .DESCRIPTION
        Reads fresh from disk on every call - no in-memory cache, so editing the JSON file takes
        effect on the next call without reloading the module. Returns a default config object
        (version 1.0, no Logging section, which normalizes to logging disabled) when the file
        does not exist, so the module needs no config file at all to work.

        Unlike the sibling module this was ported from, an unreadable or malformed file does not
        throw: the config only drives logging here, and a diagnostic cmdlet must not be made
        unusable by a broken log setting. The problem is reported once per session with
        Write-Warning and the default config is returned.
    .PARAMETER Path
        Overrides the resolved live config path (Get-CertToolboxConfigPath). Exists mainly so
        tests can point this at a fixture file without touching the real user-profile config.
    .OUTPUTS
        PSCustomObject.
    .EXAMPLE
        Read-CertToolboxConfigFile
        Reads the live user-profile config, or returns the version-1.0 default if it doesn't
        exist yet.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [string] $Path = (Get-CertToolboxConfigPath)
    )

    $default = [PSCustomObject]@{ version = '1.0' }

    if (-not (Test-Path -Path $Path -PathType Leaf)) {
        return $default
    }

    try {
        $raw = Get-Content -Path $Path -Raw -Encoding UTF8 -ErrorAction Stop
        $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
        if ($parsed -isnot [PSCustomObject]) {
            throw 'the file does not contain a JSON object.'
        }
        $parsed
    } catch {
        if (-not $script:LoggingConfigWarned) {
            $script:LoggingConfigWarned = $true
            Write-Warning "Posh-CertToolbox configuration file '$Path' could not be read and is ignored, so logging stays disabled (this warning is shown once per session): $_"
        }
        $default
    }
}

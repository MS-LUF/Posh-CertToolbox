function ConvertFrom-CertToolboxCaaData {
    <#
    .SYNOPSIS
        Parses the text form of a CAA record into its flag, tag and value.
    .DESCRIPTION
        A CAA record's presentation format is: flags, tag, quoted value (RFC 8659, section 4.1.1),
        for example: 0 issue "letsencrypt.org". The issuer-critical bit is the high bit (128) of
        the flags byte.

        For the issue and issuewild tags the value is a CA domain optionally followed by
        semicolon-separated parameters (RFC 8659, section 4.2); CaDomain holds the domain alone,
        and is empty when the value names no CA at all (a lone ";"), which forbids issuance.
    .PARAMETER Data
        The record data as text.
    .OUTPUTS
        PSCustomObject with Flag, Critical, Tag, Value and CaDomain, or nothing when the text is
        not in the expected form.
    .EXAMPLE
        ConvertFrom-CertToolboxCaaData -Data '0 issue "letsencrypt.org"'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string] $Data
    )

    if ($Data -notmatch '^\s*(?<flag>\d+)\s+(?<tag>[A-Za-z0-9]+)\s+(?<value>.*?)\s*$') {
        Write-Warning "CAA record data not understood and ignored: $Data"
        return
    }

    $flag = [int]$Matches['flag']
    $tag = $Matches['tag'].ToLowerInvariant()
    $value = $Matches['value']
    if ($value.Length -ge 2 -and $value.StartsWith('"') -and $value.EndsWith('"')) {
        $value = $value.Substring(1, $value.Length - 2)
    }

    $caDomain = $null
    if ($tag -eq 'issue' -or $tag -eq 'issuewild') {
        $caDomain = ($value -split ';')[0].Trim()
    }

    [PSCustomObject]@{
        Flag     = $flag
        Critical = (($flag -band 128) -ne 0)
        Tag      = $tag
        Value    = $value
        CaDomain = $caDomain
    }
}

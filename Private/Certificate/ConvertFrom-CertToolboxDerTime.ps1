function ConvertFrom-CertToolboxDerTime {
    <#
    .SYNOPSIS
        Converts a DER UTCTime or GeneralizedTime element to a UTC date.
    .DESCRIPTION
        The digits are read by hand rather than with a date format string. A UTCTime carries a
        two-digit year, and how a format string expands it depends on a runtime setting that
        differs between the full framework and modern runtimes; RFC 5280 (section 4.1.2.5.1)
        fixes the rule instead: 50 and above is 19xx, below is 20xx.

        Seconds are optional in neither form as used in certificates, CRLs and OCSP responses,
        so both are expected with seconds; a fractional part, when present, is ignored.
    .PARAMETER Bytes
        The DER-encoded data.
    .PARAMETER Header
        The header of the time element (tag 0x17 for UTCTime, 0x18 for GeneralizedTime).
    .OUTPUTS
        System.DateTime, in UTC.
    .EXAMPLE
        ConvertFrom-CertToolboxDerTime -Bytes $bytes -Header $header
    #>
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes,

        [Parameter(Mandatory)]
        [PSCustomObject] $Header
    )

    $text = [System.Text.Encoding]::ASCII.GetString($Bytes, $Header.ValueOffset, $Header.Length)

    if ($Header.Tag -eq 0x17 -and $text -match '^(?<yy>\d{2})(?<rest>\d{10})') {
        $year = [int]$Matches['yy']
        if ($year -ge 50) { $year += 1900 } else { $year += 2000 }
        $rest = $Matches['rest']
    } elseif ($Header.Tag -eq 0x18 -and $text -match '^(?<yyyy>\d{4})(?<rest>\d{10})') {
        $year = [int]$Matches['yyyy']
        $rest = $Matches['rest']
    } else {
        throw [System.FormatException]::new("Not a DER time value: '$text' (tag $($Header.Tag)).")
    }

    [datetime]::new(
        $year,
        [int]$rest.Substring(0, 2),
        [int]$rest.Substring(2, 2),
        [int]$rest.Substring(4, 2),
        [int]$rest.Substring(6, 2),
        [int]$rest.Substring(8, 2),
        [System.DateTimeKind]::Utc)
}

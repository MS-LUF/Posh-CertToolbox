function Find-CertToolboxCaaRecordSet {
    <#
    .SYNOPSIS
        Finds the CAA record set that applies to a DNS name, climbing towards the root.
    .DESCRIPTION
        Implements the RFC 8659 (section 3) lookup: query the name itself, and while no CAA
        record is found, remove the leftmost label and query again, up to and including the
        top-level domain. The first name that has CAA records gives the relevant record set;
        if none has any, no CAA restriction applies.

        A response can carry the CNAME records the resolver followed, so only answers of type
        CAA are kept. A name that does not exist (NXDOMAIN) has no record set and the climb
        continues. Any other DNS failure throws: RFC 8659 requires a lookup failure not to be
        treated as "no CAA records".
    .PARAMETER Name
        The DNS name to look up.
    .PARAMETER TimeoutSec
        Timeout, in seconds, of each DNS query.
    .OUTPUTS
        PSCustomObject with RecordSetName (the name the records were found on, or $null),
        Record (the parsed records) and QueriedName (every name queried, in order).
    .EXAMPLE
        Find-CertToolboxCaaRecordSet -Name 'www.example.com'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter()]
        [int] $TimeoutSec = 10
    )

    $labels = @($Name.Trim().TrimEnd('.') -split '\.' | Where-Object { $_ })
    $queriedName = New-Object System.Collections.Generic.List[string]
    $recordSetName = $null
    $record = @()

    for ($start = 0; $start -lt $labels.Count; $start++) {
        $candidate = ($labels[$start..($labels.Count - 1)]) -join '.'
        $queriedName.Add($candidate)

        $response = Invoke-CertToolboxDnsQuery -Name $candidate -Type 'CAA' -TimeoutSec $TimeoutSec
        if ($response.Status -ne 0 -and $response.Status -ne 3) {
            throw "DNS query for CAA records of '$candidate' failed with response code $($response.Status)."
        }

        # '.Answer' is absent from the response when there is none; under PS 5.1 and 7 alike a
        # missing property reads as $null, and the Where-Object guard drops it.
        $caaAnswer = @($response.Answer | Where-Object { $_ -and $_.type -eq $script:CertToolboxCaaRecordType })
        if ($caaAnswer.Count -gt 0) {
            $recordSetName = $candidate
            $record = @(foreach ($answer in $caaAnswer) {
                    $parsed = ConvertFrom-CertToolboxCaaData -Data $answer.data
                    if ($parsed) {
                        $parsed | Add-Member -NotePropertyName Ttl -NotePropertyValue $answer.TTL -PassThru
                    }
                })
            break
        }
    }

    [PSCustomObject]@{
        RecordSetName = $recordSetName
        Record        = $record
        QueriedName   = $queriedName.ToArray()
    }
}

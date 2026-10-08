function Get-CertToolboxCaaRecord {
    <#
    .SYNOPSIS
        Gets the DNS CAA records that apply to a domain, telling which CAs may issue for it.
    .DESCRIPTION
        Looks up the CAA record set relevant to each name the way a CA has to (RFC 8659): the
        name itself first, then each parent domain in turn until a CAA record set is found. The
        output says which name the records were found on.

        HasCaaRecord is $false when no CAA record exists anywhere up the tree: issuance is not
        restricted, any CA may issue.

        Issue lists the CA domains allowed to issue. IssueRestricted is $true when the record
        set has at least one "issue" record; an empty Issue list with IssueRestricted $true
        means no CA may issue at all.

        IssueWild is the same for wildcard certificates. When the record set has no "issuewild"
        record, wildcard issuance follows the "issue" records, and IssueWild repeats them.

        Record holds every record of the set as returned, including tags this cmdlet does not
        interpret.

        DNS is queried through Google's DNS-over-HTTPS API (dns.google), so it works identically
        on every platform; the names queried are sent to that service.
    .PARAMETER Name
        One or more DNS names. A leading "*." is ignored, so a wildcard name can be given as is.
    .PARAMETER TimeoutSec
        Timeout, in seconds, of each DNS query.
    .INPUTS
        System.String. Names can be piped in, as strings or as objects with a Name property.
    .OUTPUTS
        PSCustomObject (type name CertToolbox.CaaRecord), one per name.
    .EXAMPLE
        Get-CertToolboxCaaRecord -Name 'www.example.com'

        Shows which CAs may issue for www.example.com and where the restriction is defined.
    .EXAMPLE
        'example.com', 'example.org' | Get-CertToolboxCaaRecord | Select-Object Name, RecordSetName, Issue, IssueWild
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Domain', 'DnsName', 'HostName')]
        [ValidateNotNullOrEmpty()]
        [string[]] $Name,

        [Parameter()]
        [ValidateRange(1, 600)]
        [int] $TimeoutSec = 10
    )

    begin {
        $config = Read-CertToolboxConfigFile
        Write-CertToolboxLog -Config $config -Level Debug -CmdletName $MyInvocation.MyCommand.Name `
            -Message 'Cmdlet invoked' -BoundParameters $PSBoundParameters
    }

    process {
        foreach ($item in $Name) {
            try {
                $lookupName = $item.Trim().TrimEnd('.')
                if ($lookupName.StartsWith('*.')) {
                    $lookupName = $lookupName.Substring(2)
                }
                if (-not $lookupName) {
                    throw "'$item' is not a DNS name."
                }

                $recordSet = Find-CertToolboxCaaRecordSet -Name $lookupName -TimeoutSec $TimeoutSec
                $record = @($recordSet.Record)

                $issueRecord = @($record | Where-Object { $_.Tag -eq 'issue' })
                $issueWildRecord = @($record | Where-Object { $_.Tag -eq 'issuewild' })
                $issue = @($issueRecord | ForEach-Object { $_.CaDomain } | Where-Object { $_ })

                # RFC 8659, section 4.3: issuewild, when present, takes precedence over issue for
                # wildcard requests; otherwise the issue records apply to them too.
                if ($issueWildRecord.Count -gt 0) {
                    $issueWild = @($issueWildRecord | ForEach-Object { $_.CaDomain } | Where-Object { $_ })
                    $issueWildRestricted = $true
                } else {
                    $issueWild = $issue
                    $issueWildRestricted = ($issueRecord.Count -gt 0)
                }

                $summary = "No CAA record set found (queried: $(@($recordSet.QueriedName) -join ', '))."
                if ($record.Count -gt 0) {
                    $summary = "CAA record set found on '$($recordSet.RecordSetName)': issue=[$($issue -join ', ')] issuewild=[$($issueWild -join ', ')]."
                }
                Write-CertToolboxLog -Config $config -Level Information -CmdletName $MyInvocation.MyCommand.Name `
                    -Target $item -Message $summary

                [PSCustomObject]@{
                    PSTypeName          = 'CertToolbox.CaaRecord'
                    Name                = $item
                    HasCaaRecord        = ($record.Count -gt 0)
                    RecordSetName       = $recordSet.RecordSetName
                    IssueRestricted     = ($issueRecord.Count -gt 0)
                    Issue               = $issue
                    IssueWildRestricted = $issueWildRestricted
                    IssueWild           = $issueWild
                    Iodef               = @($record | Where-Object { $_.Tag -eq 'iodef' } | ForEach-Object { $_.Value })
                    Record              = $record
                    QueriedName         = @($recordSet.QueriedName)
                }
            } catch {
                $exception = Resolve-CertToolboxException -Exception $_.Exception
                Write-CertToolboxLog -Config $config -Level Error -CmdletName $MyInvocation.MyCommand.Name `
                    -Target $item -Message "CAA lookup failed: $($exception.Message)"
                $PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]::new(
                        $exception, 'CaaLookupFailed', [System.Management.Automation.ErrorCategory]::ResourceUnavailable, $item))
            }
        }
    }
}

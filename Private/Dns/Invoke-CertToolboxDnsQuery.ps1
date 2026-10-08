function Invoke-CertToolboxDnsQuery {
    <#
    .SYNOPSIS
        Sends one DNS query through Google's DNS-over-HTTPS JSON API.
    .DESCRIPTION
        The module's only DNS transport: it behaves the same
        on every platform, unlike the Windows-only Resolve-DnsName. Note that the queried name
        is sent to dns.google.

        Returns the API's JSON response as is. Status is the DNS response code (0 NOERROR,
        2 SERVFAIL, 3 NXDOMAIN); Answer, when present, is the list of records, each with name,
        type (numeric), TTL and data.
    .PARAMETER Name
        The DNS name to query.
    .PARAMETER Type
        The record type, by name (for example CAA or TXT).
    .PARAMETER TimeoutSec
        HTTP request timeout, in seconds.
    .OUTPUTS
        PSCustomObject, the deserialized JSON response.
    .EXAMPLE
        Invoke-CertToolboxDnsQuery -Name 'example.com' -Type 'CAA'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [string] $Type,

        [Parameter()]
        [int] $TimeoutSec = 10
    )

    $uri = '{0}?name={1}&type={2}' -f $script:CertToolboxDnsEndpoint, [System.Uri]::EscapeDataString($Name), [System.Uri]::EscapeDataString($Type)
    Write-Verbose "DNS query: $uri"
    Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec $TimeoutSec -ErrorAction Stop
}

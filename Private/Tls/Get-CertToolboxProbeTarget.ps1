function Get-CertToolboxProbeTarget {
    <#
    .SYNOPSIS
        Turns the host names given to a cmdlet into the list of endpoints to probe.
    .DESCRIPTION
        By default each name is one target, and the connection goes to the first of its
        addresses that answers.

        With EveryAddress each name becomes one target per address it resolves to, so that
        every node behind a load-balanced name is probed on its own; AddressFamily narrows
        that to IPv4 or IPv6. A name that does not resolve gives a single target carrying the
        error, so that the caller reports it for that name and carries on with the others.
    .PARAMETER HostName
        The DNS names or IP addresses given to the cmdlet.
    .PARAMETER EveryAddress
        Give one target per address of each name.
    .PARAMETER AddressFamily
        With EveryAddress, keep only IPv4 or only IPv6 addresses.
    .OUTPUTS
        PSCustomObject with HostName, Address (the address to connect to, or $null to let the
        connection choose), Label (how to name the target in messages) and Error (set when the
        name could not be resolved).
    .EXAMPLE
        Get-CertToolboxProbeTarget -HostName 'www.example.com' -EveryAddress
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string[]] $HostName,

        [Parameter()]
        [switch] $EveryAddress,

        [Parameter()]
        [string] $AddressFamily
    )

    foreach ($name in $HostName) {
        if (-not $EveryAddress) {
            [PSCustomObject]@{ HostName = $name; Address = $null; Label = $name; Error = $null }
            continue
        }

        $resolveParameter = @{ HostName = $name }
        if ($AddressFamily) {
            $resolveParameter.AddressFamily = $AddressFamily
        }

        try {
            $addresses = @(Resolve-CertToolboxHostAddress @resolveParameter)
        } catch {
            [PSCustomObject]@{
                HostName = $name
                Address  = $null
                Label    = $name
                Error    = Resolve-CertToolboxException -Exception $_.Exception
            }
            continue
        }

        foreach ($address in $addresses) {
            [PSCustomObject]@{ HostName = $name; Address = $address; Label = "$name [$address]"; Error = $null }
        }
    }
}

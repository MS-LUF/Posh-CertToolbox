function Resolve-CertToolboxHostAddress {
    <#
    .SYNOPSIS
        Returns the IP addresses a host name resolves to, optionally of one family only.
    .DESCRIPTION
        Asks the operating system's resolver, so the answer is what this machine sees: a large
        service gives different addresses to different resolvers and locations, and may rotate
        or truncate the list. An IP address given in place of a name is returned as is.

        Kept in its own function so that the callers can be tested without a real resolver.

        Throws when the name does not resolve, and when it has no address of the family asked
        for.
    .PARAMETER HostName
        The DNS name, or IP address, to resolve.
    .PARAMETER AddressFamily
        Keep only IPv4 or only IPv6 addresses.
    .OUTPUTS
        System.Net.IPAddress, one per address, in the order the resolver gives them.
    .EXAMPLE
        Resolve-CertToolboxHostAddress -HostName 'www.example.com' -AddressFamily IPv4
    #>
    [CmdletBinding()]
    [OutputType([System.Net.IPAddress])]
    param(
        [Parameter(Mandatory)]
        [string] $HostName,

        [Parameter()]
        [ValidateSet('IPv4', 'IPv6')]
        [string] $AddressFamily
    )

    $addresses = @([System.Net.Dns]::GetHostAddresses($HostName))

    if ($AddressFamily) {
        $wanted = [System.Net.Sockets.AddressFamily]::InterNetwork
        if ($AddressFamily -eq 'IPv6') {
            $wanted = [System.Net.Sockets.AddressFamily]::InterNetworkV6
        }
        $addresses = @($addresses | Where-Object { $_.AddressFamily -eq $wanted })
        if ($addresses.Count -eq 0) {
            throw [System.InvalidOperationException]::new("'$HostName' has no $AddressFamily address.")
        }
    }

    if ($addresses.Count -eq 0) {
        throw [System.Net.Sockets.SocketException]::new([int][System.Net.Sockets.SocketError]::HostNotFound)
    }

    foreach ($address in $addresses) {
        $address
    }
}

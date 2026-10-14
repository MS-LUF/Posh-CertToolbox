function Connect-CertToolboxTcpClient {
    <#
    .SYNOPSIS
        Opens a TCP connection to a host and port, with a timeout.
    .DESCRIPTION
        Resolves the host name and tries each returned address in turn, creating the socket for
        that address's own family - the parameterless TcpClient constructor is IPv4-only on
        the full framework, which would make an IPv6-only host unreachable under Windows
        PowerShell 5.1.

        The connect timeout is enforced by waiting on the connect task; the same value is then
        set as the socket's send and receive timeout, which is what bounds the synchronous TLS
        handshake done afterwards (see Invoke-CertToolboxTlsHandshake).
    .PARAMETER HostName
        DNS name or IP address to connect to.
    .PARAMETER Port
        TCP port to connect to.
    .PARAMETER TimeoutMs
        Timeout, in milliseconds, applied to each connection attempt and then to socket reads
        and writes.
    .PARAMETER Address
        Connect to this address and no other, instead of resolving HostName. This is how one
        particular node behind a name is reached.
    .PARAMETER AddressFamily
        When resolving HostName, use only its IPv4 or only its IPv6 addresses.
    .OUTPUTS
        System.Net.Sockets.TcpClient, connected. The caller owns it and must close it.
    .EXAMPLE
        $client = Connect-CertToolboxTcpClient -HostName 'example.com' -Port 443 -TimeoutMs 10000
    #>
    [CmdletBinding()]
    [OutputType([System.Net.Sockets.TcpClient])]
    param(
        [Parameter(Mandatory)]
        [string] $HostName,

        [Parameter(Mandatory)]
        [int] $Port,

        [Parameter()]
        [int] $TimeoutMs = 10000,

        [Parameter()]
        [System.Net.IPAddress] $Address,

        [Parameter()]
        [ValidateSet('IPv4', 'IPv6')]
        [string] $AddressFamily
    )

    if ($Address) {
        $addresses = @($Address)
    } else {
        $resolveParameter = @{ HostName = $HostName }
        if ($AddressFamily) {
            $resolveParameter.AddressFamily = $AddressFamily
        }
        $addresses = @(Resolve-CertToolboxHostAddress @resolveParameter)
    }

    $lastException = $null
    foreach ($address in $addresses) {
        $client = [System.Net.Sockets.TcpClient]::new($address.AddressFamily)
        try {
            Write-Verbose "Connecting to $address port $Port (timeout $TimeoutMs ms)."
            $task = $client.ConnectAsync($address, $Port)
            if (-not $task.Wait($TimeoutMs)) {
                throw [System.TimeoutException]::new("Connecting to ${address}:$Port timed out after $TimeoutMs ms.")
            }
            $client.ReceiveTimeout = $TimeoutMs
            $client.SendTimeout = $TimeoutMs
            return $client
        } catch {
            $client.Close()
            $lastException = Resolve-CertToolboxException -Exception $_.Exception
            Write-Verbose "Connection to $address port $Port failed: $($lastException.Message)"
        }
    }

    throw $lastException
}

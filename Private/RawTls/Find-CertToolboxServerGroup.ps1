function Find-CertToolboxServerGroup {
    <#
    .SYNOPSIS
        Finds the key-exchange groups a server accepts for one protocol version.
    .DESCRIPTION
        TLS 1.3: each group is offered alone. A server that accepts it either uses it (when a
        key share was sent, which is the case for x25519) or asks for a key share of it; a
        server that does not, refuses. One connection per group tried.

        Up to TLS 1.2: only the ECDHE suites the server accepts are offered, with every group;
        the server names the curve it picked in its key exchange message. That curve is
        removed and the hello sent again until the server refuses, which gives the curves in
        the server's order of preference. A server with no ECDHE suite has no group to report.
        The finite-field groups of DHE suites are not reported: before TLS 1.3 the server
        sends its own parameters instead of naming a group.
    .PARAMETER Connection
        The connection settings, as a hashtable of Invoke-CertToolboxRawHello parameters.
    .PARAMETER Protocol
        The protocol version to probe.
    .PARAMETER CipherSuite
        The cipher suites the server accepts for that version, by their IANA number.
    .OUTPUTS
        PSCustomObject with Group (IANA numbers) and ConnectionCount.
    .EXAMPLE
        Find-CertToolboxServerGroup -Connection $connection -Protocol Tls13 -CipherSuite 0x1301, 0x1302
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Connection,

        [Parameter(Mandatory)]
        [ValidateSet('Ssl3', 'Tls', 'Tls11', 'Tls12', 'Tls13')]
        [string] $Protocol,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [int[]] $CipherSuite
    )

    $wanted = $script:CertToolboxTlsVersionCode[$Protocol]
    $found = [System.Collections.Generic.List[int]]::new()
    $connectionCount = 0

    if ($CipherSuite.Count -eq 0) {
        return [PSCustomObject]@{ Group = [int[]]@(); ConnectionCount = 0 }
    }

    if ($Protocol -eq 'Tls13') {
        foreach ($candidate in $script:CertToolboxTls13ProbeGroup) {
            $answer = Invoke-CertToolboxRawHello @Connection -Protocol $Protocol -CipherSuite $CipherSuite -Group @($candidate)
            $connectionCount++
            if ($answer.Error -and $answer.Stage -eq 'Connect') {
                break
            }
            if ($answer.ServerHello -and $answer.Version -eq $wanted -and $answer.Group -eq $candidate) {
                $found.Add($candidate)
            }
        }
    } else {
        $ephemeral = [int[]]@($CipherSuite | Where-Object { $script:CertToolboxCipherSuiteName[$_] -cmatch '_ECDHE_' })
        $remaining = [System.Collections.Generic.List[int]]::new()
        $remaining.AddRange([int[]]$script:CertToolboxLegacyProbeGroup)

        while ($ephemeral.Count -gt 0 -and $remaining.Count -gt 0) {
            $answer = Invoke-CertToolboxRawHello @Connection -Protocol $Protocol -CipherSuite $ephemeral -Group $remaining.ToArray()
            $connectionCount++
            if ($answer.Error -or -not $answer.ServerHello -or $answer.Version -ne $wanted -or
                $null -eq $answer.Group -or -not $remaining.Contains([int]$answer.Group)) {
                break
            }
            $found.Add([int]$answer.Group)
            $null = $remaining.Remove([int]$answer.Group)
        }
    }

    [PSCustomObject]@{
        Group           = $found.ToArray()
        ConnectionCount = $connectionCount
    }
}

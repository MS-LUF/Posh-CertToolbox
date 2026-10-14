function Find-CertToolboxServerCipherSuite {
    <#
    .SYNOPSIS
        Finds every cipher suite a server accepts for one protocol version, in the order it
        chooses them.
    .DESCRIPTION
        Offers every suite of the registry that applies to the version; the server picks one.
        That suite is removed from the offer and the hello is sent again, until the server
        refuses: the suites picked, in that order, are the ones it accepts. This costs one
        connection per accepted suite, plus the one that is refused.

        The version counts as accepted only if the server answers with that very version: a
        server that does not speak it may answer with a lower one instead of refusing.

        Whether the order found is the server's own is then checked with one more connection,
        offering the suites found in reverse: a server that imposes its preference still picks
        its first choice, a server that follows the client's picks the other end.
    .PARAMETER Connection
        The connection settings, as a hashtable of Invoke-CertToolboxRawHello parameters
        (HostName, Port, and optionally TargetHost, TimeoutMs, StartTls, SmtpEhloName).
    .PARAMETER Protocol
        The protocol version to probe.
    .OUTPUTS
        PSCustomObject with Protocol, Accepted, Reason (why not, when not accepted),
        CipherSuite (IANA numbers, in the order chosen), ServerCipherOrder ($true, $false, or
        $null when it could not be told), FirstAnswer (the server's answer to the full offer),
        ConnectFailed and ConnectionCount.
    .EXAMPLE
        Find-CertToolboxServerCipherSuite -Connection @{ HostName = 'www.example.com'; Port = 443 } -Protocol Tls12
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Connection,

        [Parameter(Mandatory)]
        [ValidateSet('Ssl3', 'Tls', 'Tls11', 'Tls12', 'Tls13')]
        [string] $Protocol
    )

    if ($Protocol -eq 'Tls13') {
        $offer = $script:CertToolboxTls13CipherSuite
        $group = $script:CertToolboxTls13ProbeGroup
    } else {
        $offer = $script:CertToolboxLegacyCipherSuite
        $group = $script:CertToolboxLegacyProbeGroup
    }
    $wanted = $script:CertToolboxTlsVersionCode[$Protocol]

    $remaining = [System.Collections.Generic.List[int]]::new()
    $remaining.AddRange([int[]]$offer)
    $found = [System.Collections.Generic.List[int]]::new()
    $firstAnswer = $null
    $reason = $null
    $connectFailed = $false
    $connectionCount = 0

    while ($remaining.Count -gt 0) {
        $answer = Invoke-CertToolboxRawHello @Connection -Protocol $Protocol -CipherSuite $remaining.ToArray() -Group $group
        $connectionCount++

        $stop = $null
        if ($answer.Error) {
            $stop = $answer.Error
            if ($found.Count -eq 0) {
                $connectFailed = ($answer.Stage -eq 'Connect')
            }
        } elseif (-not $answer.ServerHello) {
            if ($answer.Alert) {
                $stop = "The server refused with the alert '$($answer.Alert)'."
            } else {
                $stop = 'The server did not answer with a ServerHello.'
            }
        } elseif ($answer.Version -ne $wanted) {
            $other = $script:CertToolboxTlsVersionCode.Keys | Where-Object { $script:CertToolboxTlsVersionCode[$_] -eq $answer.Version }
            if (-not $other) {
                $other = 'version 0x{0:X4}' -f $answer.Version
            }
            $stop = "The server answered with $other instead."
        } elseif (-not $remaining.Contains([int]$answer.CipherSuite)) {
            $stop = 'The server chose a cipher suite that was not offered.'
        }

        if ($stop) {
            if ($found.Count -eq 0) {
                $reason = $stop
            }
            break
        }

        if (-not $firstAnswer) {
            $firstAnswer = $answer
        }
        $found.Add([int]$answer.CipherSuite)
        $null = $remaining.Remove([int]$answer.CipherSuite)
    }

    $serverOrder = $null
    if ($found.Count -ge 2) {
        $reversed = $found.ToArray()
        [System.Array]::Reverse($reversed)
        $answer = Invoke-CertToolboxRawHello @Connection -Protocol $Protocol -CipherSuite $reversed -Group $group
        $connectionCount++
        if ($answer.ServerHello -and -not $answer.Error) {
            $serverOrder = ([int]$answer.CipherSuite -eq $found[0])
        }
    }

    [PSCustomObject]@{
        Protocol          = $Protocol
        Accepted          = ($found.Count -gt 0)
        Reason            = $reason
        CipherSuite       = $found.ToArray()
        ServerCipherOrder = $serverOrder
        FirstAnswer       = $firstAnswer
        ConnectFailed     = $connectFailed
        ConnectionCount   = $connectionCount
    }
}

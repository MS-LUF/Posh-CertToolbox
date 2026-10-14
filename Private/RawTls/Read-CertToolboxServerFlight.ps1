function Read-CertToolboxServerFlight {
    <#
    .SYNOPSIS
        Reads a server's answer to a ClientHello, as far as it can be read without keys.
    .DESCRIPTION
        Reads records until the server has said everything it says in the clear:

        Up to TLS 1.2 that is the whole first flight, ending with ServerHelloDone: the
        ServerHello, the certificate chain exactly as sent, a certificate status message when
        the server staples an OCSP response, and the key exchange message, from which the
        elliptic curve is read.

        In TLS 1.3 only the ServerHello is in the clear, so reading stops right after it.

        An alert in place of a ServerHello is the server refusing the offer; its description
        is returned in Alert. Handshake messages can be split across records or share one, so
        they are reassembled before being decoded.

        If the connection fails after the ServerHello, what was read is returned with Complete
        set to $false; before it, the failure is thrown.
    .PARAMETER Stream
        The connected stream, on which the ClientHello has just been sent.
    .OUTPUTS
        PSCustomObject with ServerHello (whether one was received), Version, CipherSuite, Group,
        HelloRetryRequest, ExtendedMasterSecret, SecureRenegotiation, Alert, Certificate (the
        chain as sent), OcspStapled and Complete.
    .EXAMPLE
        Read-CertToolboxServerFlight -Stream $client.GetStream()
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [System.IO.Stream] $Stream
    )

    $result = [PSCustomObject]@{
        ServerHello          = $false
        Version              = $null
        CipherSuite          = $null
        Group                = $null
        HelloRetryRequest    = $false
        ExtendedMasterSecret = $false
        SecureRenegotiation  = $false
        Alert                = $null
        Certificate          = @()
        OcspStapled          = $false
        Complete             = $false
    }

    $certificates = [System.Collections.Generic.List[object]]::new()
    $pending = [System.Collections.Generic.List[byte]]::new()
    $finished = $false

    try {
        while (-not $finished) {
            $record = Read-CertToolboxTlsRecord -Stream $Stream

            if ($record.Type -eq 21) {
                $code = 0
                if ($record.Payload.Length -ge 2) {
                    $code = [int]$record.Payload[1]
                }
                $result.Alert = $script:CertToolboxTlsAlertName[$code]
                if (-not $result.Alert) {
                    $result.Alert = "alert_$code"
                }
                break
            }
            if ($record.Type -ne 22) {
                # Change cipher spec or encrypted data: nothing further is readable.
                break
            }

            $pending.AddRange($record.Payload)
            $buffer = $pending.ToArray()
            $offset = 0

            while ($offset + 4 -le $buffer.Length) {
                $type = [int]$buffer[$offset]
                $size = ([int]$buffer[$offset + 1] -shl 16) -bor ([int]$buffer[$offset + 2] -shl 8) -bor [int]$buffer[$offset + 3]
                $body = $offset + 4
                if ($body + $size -gt $buffer.Length) {
                    # The rest of this message is in the next record.
                    break
                }

                switch ($type) {
                    2 {
                        $hello = ConvertFrom-CertToolboxServerHello -Bytes $buffer -Offset $body -Length $size
                        $result.ServerHello = $true
                        $result.Version = $hello.Version
                        $result.CipherSuite = $hello.CipherSuite
                        $result.Group = $hello.Group
                        $result.HelloRetryRequest = $hello.HelloRetryRequest
                        $result.ExtendedMasterSecret = $hello.ExtendedMasterSecret
                        $result.SecureRenegotiation = $hello.SecureRenegotiation
                        if ($hello.Version -ge 0x0304) {
                            $finished = $true
                        }
                    }
                    11 {
                        # Certificate: a three-byte list length, then each certificate behind
                        # its own three-byte length.
                        $position = $body + 3
                        $listEnd = $body + $size
                        while ($position + 3 -le $listEnd) {
                            $length = ([int]$buffer[$position] -shl 16) -bor ([int]$buffer[$position + 1] -shl 8) -bor [int]$buffer[$position + 2]
                            $position += 3
                            if ($position + $length -gt $listEnd) {
                                break
                            }
                            $raw = New-Object byte[] $length
                            [System.Array]::Copy($buffer, $position, $raw, 0, $length)
                            try {
                                $certificates.Add([System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$raw))
                            } catch {
                                Write-Verbose "A certificate of the server's chain could not be decoded: $($_.Exception.Message)"
                            }
                            $position += $length
                        }
                    }
                    22 {
                        $result.OcspStapled = $true
                    }
                    12 {
                        # ServerKeyExchange for ECDHE starts with the curve type; 3 is a named
                        # curve, followed by its two-byte number.
                        if ($size -ge 3 -and $buffer[$body] -eq 3) {
                            $result.Group = ([int]$buffer[$body + 1] -shl 8) -bor [int]$buffer[$body + 2]
                        }
                    }
                    14 {
                        $finished = $true
                    }
                }

                $offset = $body + $size
                if ($finished) {
                    break
                }
            }

            if ($offset -gt 0) {
                $pending.RemoveRange(0, $offset)
            }
        }
        $result.Complete = $true
    } catch {
        if (-not $result.ServerHello) {
            throw
        }
        Write-Verbose "The server's answer could not be read to its end: $((Resolve-CertToolboxException -Exception $_.Exception).Message)"
    }

    $result.Certificate = $certificates.ToArray()
    $result
}

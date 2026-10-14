function ConvertFrom-CertToolboxServerHello {
    <#
    .SYNOPSIS
        Decodes the body of a TLS ServerHello message.
    .DESCRIPTION
        Returns what the server chose: the protocol version (taken from the supported versions
        extension when present, which is how TLS 1.3 states it), the cipher suite, the
        key-exchange group when the server names one in a key share extension, and whether it
        acknowledged the extended master secret and renegotiation info extensions.

        A TLS 1.3 server that accepts the offer but wants a key share for another group answers
        with a HelloRetryRequest, which is a ServerHello carrying a fixed, well-known random
        value (RFC 8446, section 4.1.3); it is recognised by that value.
    .PARAMETER Bytes
        The data holding the message.
    .PARAMETER Offset
        Index of the first byte of the message body, after its four-byte handshake header.
    .PARAMETER Length
        Length of the message body.
    .OUTPUTS
        PSCustomObject with Version, CipherSuite, Group ($null when not stated),
        HelloRetryRequest, ExtendedMasterSecret and SecureRenegotiation.
    .EXAMPLE
        ConvertFrom-CertToolboxServerHello -Bytes $message -Offset 4 -Length ($message.Length - 4)
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes,

        [Parameter(Mandatory)]
        [int] $Offset,

        [Parameter(Mandatory)]
        [int] $Length
    )

    $end = $Offset + $Length
    # version (2) + random (32) + session id length (1) + cipher suite (2) + compression (1)
    if ($Length -lt 38 -or $end -gt $Bytes.Length) {
        throw [System.FormatException]::new('The ServerHello message is truncated.')
    }

    $result = [PSCustomObject]@{
        Version              = ([int]$Bytes[$Offset] -shl 8) -bor [int]$Bytes[$Offset + 1]
        CipherSuite          = $null
        Group                = $null
        HelloRetryRequest    = $false
        ExtendedMasterSecret = $false
        SecureRenegotiation  = $false
    }

    $random = [System.BitConverter]::ToString($Bytes, $Offset + 2, 32)
    $result.HelloRetryRequest = ($random -eq 'CF-21-AD-74-E5-9A-61-11-BE-1D-8C-02-1E-65-B8-91-C2-A2-11-16-7A-BB-8C-5E-07-9E-09-E2-C8-A8-33-9C')

    $position = $Offset + 34
    $position += 1 + [int]$Bytes[$position]
    if ($position + 3 -gt $end) {
        throw [System.FormatException]::new('The ServerHello message is truncated.')
    }
    $result.CipherSuite = ([int]$Bytes[$position] -shl 8) -bor [int]$Bytes[$position + 1]
    $position += 3

    if ($position + 2 -le $end) {
        $extensionEnd = $position + 2 + (([int]$Bytes[$position] -shl 8) -bor [int]$Bytes[$position + 1])
        $position += 2
        if ($extensionEnd -gt $end) {
            $extensionEnd = $end
        }
        while ($position + 4 -le $extensionEnd) {
            $type = ([int]$Bytes[$position] -shl 8) -bor [int]$Bytes[$position + 1]
            $size = ([int]$Bytes[$position + 2] -shl 8) -bor [int]$Bytes[$position + 3]
            $data = $position + 4
            if ($data + $size -gt $extensionEnd) {
                break
            }
            switch ($type) {
                43 { if ($size -ge 2) { $result.Version = ([int]$Bytes[$data] -shl 8) -bor [int]$Bytes[$data + 1] } }
                51 { if ($size -ge 2) { $result.Group = ([int]$Bytes[$data] -shl 8) -bor [int]$Bytes[$data + 1] } }
                23 { $result.ExtendedMasterSecret = $true }
                0xFF01 { $result.SecureRenegotiation = $true }
            }
            $position = $data + $size
        }
    }

    $result
}

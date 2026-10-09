function ConvertFrom-CertToolboxOcspResponse {
    <#
    .SYNOPSIS
        Decodes an OCSP response into the responder's status and the certificate's status.
    .DESCRIPTION
        Reads the response by hand (RFC 6960, section 4.2). ResponseStatus is the responder's
        own verdict on the request (Successful, or an error such as Unauthorized or TryLater);
        only a successful response carries a certificate status, which is Good, Revoked or
        Unknown, with the dates the responder gives for it.

        Only the first single response is read: the request asked about one certificate.

        The response's signature is not verified: this reads what the responder answered.
    .PARAMETER Bytes
        The response body as received.
    .OUTPUTS
        PSCustomObject with ResponseStatus, CertificateStatus, ProducedAt, ThisUpdate and
        NextUpdate (the last four $null when the response is not successful).
    .EXAMPLE
        ConvertFrom-CertToolboxOcspResponse -Bytes $responseBytes
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes
    )

    $outer = Read-CertToolboxDerHeader -Bytes $Bytes -Offset 0
    if (-not $outer -or $outer.Tag -ne 0x30) {
        throw [System.FormatException]::new('The data is not an OCSP response.')
    }
    $top = @(Get-CertToolboxDerChild -Bytes $Bytes -Parent $outer)
    if ($top.Count -lt 1 -or $top[0].Tag -ne 0x0A -or $top[0].Length -lt 1) {
        throw [System.FormatException]::new('The OCSP response has no status.')
    }

    $statusName = @{
        0 = 'Successful'
        1 = 'MalformedRequest'
        2 = 'InternalError'
        3 = 'TryLater'
        5 = 'SigRequired'
        6 = 'Unauthorized'
    }
    $statusCode = [int]$Bytes[$top[0].ValueOffset]
    $responseStatus = $statusName[$statusCode]
    if (-not $responseStatus) {
        $responseStatus = "Status$statusCode"
    }

    $result = [PSCustomObject]@{
        ResponseStatus    = $responseStatus
        CertificateStatus = $null
        ProducedAt        = $null
        ThisUpdate        = $null
        NextUpdate        = $null
    }
    if ($statusCode -ne 0) {
        return $result
    }
    if ($top.Count -lt 2) {
        throw [System.FormatException]::new('The OCSP response is successful but carries no data.')
    }

    # responseBytes [0] { SEQUENCE { responseType OID, response OCTET STRING { BasicOCSPResponse } } }
    $responseBytes = @(Get-CertToolboxDerChild -Bytes $Bytes -Parent (@(Get-CertToolboxDerChild -Bytes $Bytes -Parent $top[1])[0]))
    $basic = Read-CertToolboxDerHeader -Bytes $Bytes -Offset $responseBytes[1].ValueOffset
    $tbs = @(Get-CertToolboxDerChild -Bytes $Bytes -Parent $basic)[0]

    # ResponseData ::= SEQUENCE { version [0] OPTIONAL, responderID, producedAt, responses, ... }
    $field = @(Get-CertToolboxDerChild -Bytes $Bytes -Parent $tbs)
    $index = 0
    if ($field[0].Tag -eq 0xA0) {
        $index = 1
    }
    $result.ProducedAt = ConvertFrom-CertToolboxDerTime -Bytes $Bytes -Header $field[$index + 1]

    # SingleResponse ::= SEQUENCE { certID, certStatus, thisUpdate, nextUpdate [0] OPTIONAL, ... }
    $single = @(Get-CertToolboxDerChild -Bytes $Bytes -Parent (@(Get-CertToolboxDerChild -Bytes $Bytes -Parent $field[$index + 2])[0]))

    # certStatus is a context tag: [0] good, [1] revoked, [2] unknown.
    switch ($single[1].Tag -band 0x1F) {
        0 { $result.CertificateStatus = 'Good' }
        1 { $result.CertificateStatus = 'Revoked' }
        default { $result.CertificateStatus = 'Unknown' }
    }
    $result.ThisUpdate = ConvertFrom-CertToolboxDerTime -Bytes $Bytes -Header $single[2]
    if ($single.Count -gt 3 -and $single[3].Tag -eq 0xA0) {
        $nextUpdate = Read-CertToolboxDerHeader -Bytes $Bytes -Offset $single[3].ValueOffset
        $result.NextUpdate = ConvertFrom-CertToolboxDerTime -Bytes $Bytes -Header $nextUpdate
    }

    $result
}

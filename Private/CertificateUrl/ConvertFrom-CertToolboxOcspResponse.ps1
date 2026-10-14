function ConvertFrom-CertToolboxOcspResponse {
    <#
    .SYNOPSIS
        Decodes an OCSP response into the responder's status and the certificate's status, and
        verifies it when the certificates involved are given.
    .DESCRIPTION
        Reads the response by hand (RFC 6960, section 4.2). ResponseStatus is the responder's
        own verdict on the request (Successful, or an error such as Unauthorized or TryLater);
        only a successful response carries a certificate status, which is Good, Revoked or
        Unknown, with the dates the responder gives for it.

        Only the first single response is read: the request asked about one certificate.

        When the certificate and its issuer are given, the response is verified:

        It must be about that certificate: the serial number and the hashes of the issuer's
        name and key in the response must be the certificate's own.

        It must be signed either by the issuer itself, or by a responder certificate carried in
        the response that the issuer signed, that is marked for OCSP signing (extended key
        usage 1.3.6.1.5.5.7.3.9) and that is within its validity dates (RFC 6960, section
        4.2.2.2). The revocation of such a responder certificate is not checked.
    .PARAMETER Bytes
        The response body as received.
    .PARAMETER Certificate
        The certificate the request was about.
    .PARAMETER Issuer
        The certificate of the CA that issued it.
    .OUTPUTS
        PSCustomObject with ResponseStatus, CertificateStatus, ProducedAt, ThisUpdate,
        NextUpdate, Signature (Valid, Invalid or NotVerified) and SignatureDetail. All but the
        first are $null when the response is not successful.
    .EXAMPLE
        ConvertFrom-CertToolboxOcspResponse -Bytes $responseBytes -Certificate $leaf -Issuer $intermediate
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes,

        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,

        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Issuer
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
        Signature         = $null
        SignatureDetail   = $null
    }
    if ($statusCode -ne 0) {
        return $result
    }
    if ($top.Count -lt 2) {
        throw [System.FormatException]::new('The OCSP response is successful but carries no data.')
    }

    # responseBytes [0] { SEQUENCE { responseType OID, response OCTET STRING { BasicOCSPResponse } } }
    $responseBytes = @(Get-CertToolboxDerChild -Bytes $Bytes -Parent (@(Get-CertToolboxDerChild -Bytes $Bytes -Parent $top[1])[0]))
    $signed = ConvertFrom-CertToolboxSignedStructure -Bytes $Bytes -Offset $responseBytes[1].ValueOffset
    $tbs = $signed.Part[0]

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

    if (-not $Certificate -or -not $Issuer) {
        $result.Signature = 'NotVerified'
        $result.SignatureDetail = 'The issuer certificate is not available.'
        return $result
    }

    # --- Is the response about this certificate? ---
    # CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }
    $certificateId = @(Get-CertToolboxDerChild -Bytes $Bytes -Parent $single[0])
    $serial = $Certificate.GetSerialNumber()
    [System.Array]::Reverse($serial)
    $sameCertificate = [System.BitConverter]::ToString($Bytes, $certificateId[3].ValueOffset, $certificateId[3].Length) -ceq [System.BitConverter]::ToString($serial)

    if ($sameCertificate) {
        $hashOid = @(Get-CertToolboxDerChild -Bytes $Bytes -Parent $certificateId[0])[0]
        $hasher = $null
        switch ([System.BitConverter]::ToString($Bytes, $hashOid.ValueOffset, $hashOid.Length)) {
            '2B-0E-03-02-1A' { $hasher = [System.Security.Cryptography.SHA1]::Create() }
            '60-86-48-01-65-03-04-02-01' { $hasher = [System.Security.Cryptography.SHA256]::Create() }
        }
        # With a hash this module does not compute, the serial number alone has to do.
        if ($hasher) {
            try {
                $nameHash = [System.BitConverter]::ToString($hasher.ComputeHash($Certificate.IssuerName.RawData))
                $keyHash = [System.BitConverter]::ToString($hasher.ComputeHash($Issuer.PublicKey.EncodedKeyValue.RawData))
            } finally {
                $hasher.Dispose()
            }
            $sameCertificate = ($nameHash -ceq [System.BitConverter]::ToString($Bytes, $certificateId[1].ValueOffset, $certificateId[1].Length)) -and
                ($keyHash -ceq [System.BitConverter]::ToString($Bytes, $certificateId[2].ValueOffset, $certificateId[2].Length))
        }
    }
    if (-not $sameCertificate) {
        $result.Signature = 'Invalid'
        $result.SignatureDetail = 'The response is about another certificate than the one asked for.'
        return $result
    }

    # --- Who signed it? The issuer itself, or a responder certificate it delegated to. ---
    $direct = Test-CertToolboxSignature -Data $signed.ToBeSigned -Signature $signed.Signature `
        -AlgorithmOid $signed.AlgorithmOid -SignerCertificate $Issuer
    if ($direct.Status -ne 'Invalid') {
        # Valid, or an algorithm that cannot be checked whoever the signer is.
        $result.Signature = $direct.Status
        $result.SignatureDetail = $direct.Detail
        return $result
    }

    $result.Signature = 'Invalid'
    $result.SignatureDetail = 'The response is signed neither by the issuer nor by a responder certificate it carries.'

    # certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
    if ($signed.Part.Count -gt 3 -and $signed.Part[3].Tag -eq 0xA0) {
        $list = @(Get-CertToolboxDerChild -Bytes $Bytes -Parent $signed.Part[3])[0]
        foreach ($element in (Get-CertToolboxDerChild -Bytes $Bytes -Parent $list)) {
            $raw = Copy-CertToolboxByteRange -Bytes $Bytes -Offset $element.Offset -Length ($element.ValueOffset + $element.Length - $element.Offset)
            $responder = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$raw)

            $byResponder = Test-CertToolboxSignature -Data $signed.ToBeSigned -Signature $signed.Signature `
                -AlgorithmOid $signed.AlgorithmOid -SignerCertificate $responder
            if ($byResponder.Status -ne 'Valid') {
                continue
            }

            # This certificate signed the response; it now has to be entitled to.
            $name = $responder.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
            $responderSigned = ConvertFrom-CertToolboxSignedStructure -Bytes $raw
            $issuedByCa = Test-CertToolboxSignature -Data $responderSigned.ToBeSigned -Signature $responderSigned.Signature `
                -AlgorithmOid $responderSigned.AlgorithmOid -SignerCertificate $Issuer

            $usage = @($responder.Extensions |
                    Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] } |
                    ForEach-Object { $_.EnhancedKeyUsages } | ForEach-Object { $_.Value })
            $now = [datetime]::UtcNow

            if ($issuedByCa.Status -eq 'NotVerified') {
                $result.Signature = 'NotVerified'
                $result.SignatureDetail = "Signed by the responder certificate '$name', whose own signature cannot be checked: $($issuedByCa.Detail)"
            } elseif ($issuedByCa.Status -ne 'Valid') {
                $result.SignatureDetail = "Signed by the responder certificate '$name', which the certificate's issuer did not sign."
            } elseif ($usage -notcontains '1.3.6.1.5.5.7.3.9') {
                $result.SignatureDetail = "Signed by the responder certificate '$name', which is not marked for OCSP signing."
            } elseif ($now -lt $responder.NotBefore.ToUniversalTime() -or $now -gt $responder.NotAfter.ToUniversalTime()) {
                $result.SignatureDetail = "Signed by the responder certificate '$name', which is outside its validity dates."
            } else {
                $result.Signature = 'Valid'
                $result.SignatureDetail = "Signed by the delegated responder certificate '$name'."
            }
            break
        }
    }

    $result
}

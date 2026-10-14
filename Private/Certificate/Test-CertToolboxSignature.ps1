function Test-CertToolboxSignature {
    <#
    .SYNOPSIS
        Verifies a signature over some data with the public key of a certificate.
    .DESCRIPTION
        Handles the algorithms in use for certificates, CRLs and OCSP responses: RSA with
        PKCS #1 v1.5 padding and ECDSA, each with SHA-1, SHA-256, SHA-384 or SHA-512.

        An ECDSA signature is stored in these structures as a DER SEQUENCE of two integers,
        while the verification call available on every supported runtime expects the two values
        side by side at a fixed width, so it is converted here.

        Any other algorithm (RSASSA-PSS, Ed25519 and so on) is reported as NotVerified rather
        than Invalid: nothing was checked, so nothing is known.
    .PARAMETER Data
        The bytes the signature covers.
    .PARAMETER Signature
        The signature, as stored in the signed structure.
    .PARAMETER AlgorithmOid
        The signature algorithm's object identifier, as dash-separated hex bytes.
    .PARAMETER SignerCertificate
        The certificate holding the public key expected to have signed the data.
    .OUTPUTS
        PSCustomObject with Status (Valid, Invalid or NotVerified) and Detail (the reason, when
        the status is not Valid).
    .EXAMPLE
        Test-CertToolboxSignature -Data $signed.ToBeSigned -Signature $signed.Signature -AlgorithmOid $signed.AlgorithmOid -SignerCertificate $issuer
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Data,

        [Parameter(Mandatory)]
        [byte[]] $Signature,

        [Parameter(Mandatory)]
        [string] $AlgorithmOid,

        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $SignerCertificate
    )

    $algorithm = $script:CertToolboxSignatureAlgorithm[$AlgorithmOid]
    if (-not $algorithm) {
        $name = $script:CertToolboxUnsupportedSignatureAlgorithm[$AlgorithmOid]
        if (-not $name) {
            $name = "with identifier $AlgorithmOid"
        }
        return [PSCustomObject]@{ Status = 'NotVerified'; Detail = "The signature algorithm $name is not supported." }
    }

    $hashName = [System.Security.Cryptography.HashAlgorithmName]::new($algorithm.Hash)
    $key = $null
    try {
        if ($algorithm.Key -eq 'RSA') {
            $key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($SignerCertificate)
            if (-not $key) {
                return [PSCustomObject]@{ Status = 'Invalid'; Detail = 'The signature is RSA but the signer certificate has no RSA key.' }
            }
            $valid = $key.VerifyData($Data, $Signature, $hashName, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        } else {
            $key = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($SignerCertificate)
            if (-not $key) {
                return [PSCustomObject]@{ Status = 'Invalid'; Detail = 'The signature is ECDSA but the signer certificate has no ECDSA key.' }
            }

            # SEQUENCE { r INTEGER, s INTEGER } -> r || s, each left-padded to the key size.
            $sequence = Read-CertToolboxDerHeader -Bytes $Signature -Offset 0
            $integer = @(Get-CertToolboxDerChild -Bytes $Signature -Parent $sequence)
            if ($integer.Count -ne 2) {
                return [PSCustomObject]@{ Status = 'Invalid'; Detail = 'The ECDSA signature is not two integers.' }
            }
            $size = [int][Math]::Ceiling($key.KeySize / 8)
            $raw = New-Object byte[] ($size * 2)
            for ($i = 0; $i -lt 2; $i++) {
                $offset = $integer[$i].ValueOffset
                $length = $integer[$i].Length
                # A leading zero only keeps the integer positive; it is not part of the value.
                while ($length -gt $size -and $Signature[$offset] -eq 0) {
                    $offset++
                    $length--
                }
                if ($length -gt $size) {
                    return [PSCustomObject]@{ Status = 'Invalid'; Detail = 'The ECDSA signature does not fit the signer key size.' }
                }
                [System.Array]::Copy($Signature, $offset, $raw, ($i * $size) + ($size - $length), $length)
            }
            $valid = $key.VerifyData([byte[]]$Data, [byte[]]$raw, $hashName)
        }
    } catch {
        return [PSCustomObject]@{
            Status = 'Invalid'
            Detail = "The signature could not be checked: $((Resolve-CertToolboxException -Exception $_.Exception).Message)"
        }
    } finally {
        if ($key) {
            $key.Dispose()
        }
    }

    if ($valid) {
        return [PSCustomObject]@{ Status = 'Valid'; Detail = $null }
    }
    [PSCustomObject]@{ Status = 'Invalid'; Detail = 'The signature does not match the signer key.' }
}

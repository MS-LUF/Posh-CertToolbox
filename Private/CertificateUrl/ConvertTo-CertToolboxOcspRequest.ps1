function ConvertTo-CertToolboxOcspRequest {
    <#
    .SYNOPSIS
        Builds the DER-encoded OCSP request asking for the status of one certificate.
    .DESCRIPTION
        Produces the smallest valid request (RFC 6960, section 4.1): one certificate identifier,
        no extensions, no nonce, no signature.

        The certificate is identified by the SHA-1 hash of its issuer's name, the SHA-1 hash of
        its issuer's public key and its own serial number. SHA-1 is used because it is the one
        algorithm every responder is required to accept for this identifier; it identifies the
        certificate and protects nothing.

        The issuer's own certificate is needed for the key hash, which is why an OCSP test
        cannot be made for a certificate whose issuer is not available.
    .PARAMETER Certificate
        The certificate whose status is asked.
    .PARAMETER Issuer
        The certificate of the CA that issued it.
    .OUTPUTS
        System.Byte[]
    .EXAMPLE
        ConvertTo-CertToolboxOcspRequest -Certificate $leaf -Issuer $intermediate
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,

        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Issuer
    )

    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $issuerNameHash = $sha1.ComputeHash($Certificate.IssuerName.RawData)
        # The key hash covers the public key bits alone, without the algorithm identifier.
        $issuerKeyHash = $sha1.ComputeHash($Issuer.PublicKey.EncodedKeyValue.RawData)
    } finally {
        $sha1.Dispose()
    }

    # GetSerialNumber returns the INTEGER content least significant byte first.
    $serial = $Certificate.GetSerialNumber()
    [System.Array]::Reverse($serial)

    # AlgorithmIdentifier for SHA-1: OID 1.3.14.3.2.26 followed by NULL parameters.
    $algorithm = ConvertTo-CertToolboxDerElement -Tag 0x30 -Content ([byte[]](0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00))

    $certificateId = ConvertTo-CertToolboxDerElement -Tag 0x30 -Content ([byte[]](
            $algorithm +
            (ConvertTo-CertToolboxDerElement -Tag 0x04 -Content $issuerNameHash) +
            (ConvertTo-CertToolboxDerElement -Tag 0x04 -Content $issuerKeyHash) +
            (ConvertTo-CertToolboxDerElement -Tag 0x02 -Content $serial)))

    # OCSPRequest { tbsRequest { requestList { Request { reqCert } } } }
    $request = ConvertTo-CertToolboxDerElement -Tag 0x30 -Content $certificateId
    $requestList = ConvertTo-CertToolboxDerElement -Tag 0x30 -Content $request
    $tbsRequest = ConvertTo-CertToolboxDerElement -Tag 0x30 -Content $requestList
    ConvertTo-CertToolboxDerElement -Tag 0x30 -Content $tbsRequest
}

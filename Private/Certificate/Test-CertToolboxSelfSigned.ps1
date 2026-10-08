function Test-CertToolboxSelfSigned {
    <#
    .SYNOPSIS
        Tells whether a certificate's subject and issuer names are identical.
    .DESCRIPTION
        Compares the DER-encoded subject and issuer names byte for byte, which is independent of
        how each platform formats a distinguished name as text. This is a self-issued check
        (it does not verify the signature), which is what is needed to tell a root from an
        intermediate when comparing chains.
    .PARAMETER Certificate
        The certificate to examine.
    .OUTPUTS
        System.Boolean
    .EXAMPLE
        Test-CertToolboxSelfSigned -Certificate $certificate
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
    )

    $subject = [System.Convert]::ToBase64String($Certificate.SubjectName.RawData)
    $issuer = [System.Convert]::ToBase64String($Certificate.IssuerName.RawData)
    $subject -ceq $issuer
}

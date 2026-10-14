function ConvertTo-CertToolboxCertificateInfo {
    <#
    .SYNOPSIS
        Converts an X509Certificate2 into this module's flat certificate description.
    .DESCRIPTION
        Produces the object used for every certificate this module reports (leaf, server-sent
        chain, locally built chain), built only from members that behave the same on every
        platform. The original certificate object stays available in the Certificate property.
    .PARAMETER Certificate
        The certificate to describe.
    .PARAMETER Status
        Chain element status flags, for a certificate taken from a locally built chain. When
        this parameter is used the output gets a Status property (an empty list means the
        element has no error).
    .OUTPUTS
        PSCustomObject (type name CertToolbox.CertificateInfo).
    .EXAMPLE
        ConvertTo-CertToolboxCertificateInfo -Certificate $certificate
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $Status
    )

    $keySize = Get-CertToolboxPublicKeySize -Certificate $Certificate

    $isCertificateAuthority = $false
    foreach ($extension in $Certificate.Extensions) {
        if ($extension -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
            $isCertificateAuthority = $extension.CertificateAuthority
        }
    }

    $info = [PSCustomObject]@{
        PSTypeName             = 'CertToolbox.CertificateInfo'
        Subject                = $Certificate.Subject
        Issuer                 = $Certificate.Issuer
        Thumbprint             = $Certificate.Thumbprint
        SerialNumber           = $Certificate.SerialNumber
        NotBefore              = $Certificate.NotBefore
        NotAfter               = $Certificate.NotAfter
        DaysUntilExpiry        = [int][Math]::Floor(($Certificate.NotAfter - (Get-Date)).TotalDays)
        SubjectAlternativeName = @(Get-CertToolboxSubjectAlternativeName -Certificate $Certificate)
        SignatureAlgorithm     = $Certificate.SignatureAlgorithm.FriendlyName
        PublicKeyAlgorithm     = $Certificate.PublicKey.Oid.FriendlyName
        PublicKeySize          = $keySize
        IsSelfSigned           = Test-CertToolboxSelfSigned -Certificate $Certificate
        IsCertificateAuthority = $isCertificateAuthority
        Certificate            = $Certificate
    }

    if ($PSBoundParameters.ContainsKey('Status')) {
        $info | Add-Member -NotePropertyName Status -NotePropertyValue @($Status)
    }

    $info
}

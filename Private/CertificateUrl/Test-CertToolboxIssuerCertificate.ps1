function Test-CertToolboxIssuerCertificate {
    <#
    .SYNOPSIS
        Tells whether downloaded data contains the certificate of a given certificate's issuer.
    .DESCRIPTION
        A CA Issuers URL is meant to return the issuing CA's certificate. Servers publish it as
        a single DER certificate, as PEM, or as a PKCS #7 bundle of several certificates; all
        three are accepted.

        The match is made on the name: one of the returned certificates must have a subject
        identical, byte for byte, to the issuer name of the certificate being checked. The
        signature is not verified.
    .PARAMETER Bytes
        The data as downloaded.
    .PARAMETER Certificate
        The certificate whose issuer is expected.
    .OUTPUTS
        PSCustomObject with IsCertificate, Match and Subject (the subjects found, joined).
    .EXAMPLE
        Test-CertToolboxIssuerCertificate -Bytes $downloaded -Certificate $leaf
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes,

        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
    )

    $collection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    try {
        $collection.Import([byte[]]$Bytes)
    } catch {
        Write-Verbose "Downloaded issuer data is not a certificate: $($_.Exception.Message)"
    }

    if ($collection.Count -eq 0) {
        return [PSCustomObject]@{
            IsCertificate = $false
            Match         = $false
            Subject       = $null
        }
    }

    $expected = [System.Convert]::ToBase64String($Certificate.IssuerName.RawData)
    $match = $false
    foreach ($candidate in $collection) {
        if ([System.Convert]::ToBase64String($candidate.SubjectName.RawData) -ceq $expected) {
            $match = $true
        }
    }

    [PSCustomObject]@{
        IsCertificate = $true
        Match         = $match
        Subject       = (@($collection | ForEach-Object { $_.Subject }) -join ' | ')
    }
}

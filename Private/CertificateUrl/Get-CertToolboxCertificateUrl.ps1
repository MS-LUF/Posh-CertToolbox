function Get-CertToolboxCertificateUrl {
    <#
    .SYNOPSIS
        Returns the CRL, OCSP and issuer-certificate URLs embedded in a certificate.
    .DESCRIPTION
        Decodes two extensions from their DER bytes (the text the runtime produces for them
        differs per platform and is localized on Windows):

        CRL Distribution Points (2.5.29.31, RFC 5280 section 4.2.1.13): the URIs found in the
        fullName of each distribution point.

        Authority Information Access (1.3.6.1.5.5.7.1.1, RFC 5280 section 4.2.2.1): the URI of
        each access description, sorted by access method into OCSP (1.3.6.1.5.5.7.48.1) and
        CA Issuers (1.3.6.1.5.5.7.48.2).

        A malformed extension is reported on the verbose stream and yields no URL, rather than
        failing the caller.
    .PARAMETER Certificate
        The certificate to read.
    .OUTPUTS
        PSCustomObject with Crl, Ocsp and CaIssuers, each a list of URL strings (possibly empty).
    .EXAMPLE
        Get-CertToolboxCertificateUrl -Certificate $certificate
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
    )

    $crl = [System.Collections.Generic.List[string]]::new()
    $ocsp = [System.Collections.Generic.List[string]]::new()
    $caIssuers = [System.Collections.Generic.List[string]]::new()

    $distributionPoints = $Certificate.Extensions['2.5.29.31']
    if ($distributionPoints) {
        try {
            $bytes = $distributionPoints.RawData
            $sequence = Read-CertToolboxDerHeader -Bytes $bytes -Offset 0
            foreach ($point in (Get-CertToolboxDerChild -Bytes $bytes -Parent $sequence)) {
                # DistributionPoint ::= SEQUENCE { distributionPoint [0] { fullName [0] GeneralNames } ... }
                foreach ($pointName in (Get-CertToolboxDerChild -Bytes $bytes -Parent $point | Where-Object { $_.Tag -eq 0xA0 })) {
                    foreach ($fullName in (Get-CertToolboxDerChild -Bytes $bytes -Parent $pointName | Where-Object { $_.Tag -eq 0xA0 })) {
                        foreach ($name in (Get-CertToolboxDerChild -Bytes $bytes -Parent $fullName | Where-Object { $_.Tag -eq 0x86 })) {
                            $crl.Add([System.Text.Encoding]::ASCII.GetString($bytes, $name.ValueOffset, $name.Length))
                        }
                    }
                }
            }
        } catch {
            Write-Verbose "CRL Distribution Points extension of '$($Certificate.Subject)' could not be decoded: $($_.Exception.Message)"
        }
    }

    $informationAccess = $Certificate.Extensions['1.3.6.1.5.5.7.1.1']
    if ($informationAccess) {
        try {
            $bytes = $informationAccess.RawData
            $sequence = Read-CertToolboxDerHeader -Bytes $bytes -Offset 0
            foreach ($description in (Get-CertToolboxDerChild -Bytes $bytes -Parent $sequence)) {
                # AccessDescription ::= SEQUENCE { accessMethod OBJECT IDENTIFIER, accessLocation GeneralName }
                $part = @(Get-CertToolboxDerChild -Bytes $bytes -Parent $description)
                if ($part.Count -lt 2 -or $part[0].Tag -ne 0x06 -or $part[1].Tag -ne 0x86) {
                    continue
                }
                # The access method is compared as encoded: 2B 06 01 05 05 07 30 is the
                # 1.3.6.1.5.5.7.48 arc, and the last byte selects OCSP (1) or CA Issuers (2).
                $method = [System.BitConverter]::ToString($bytes, $part[0].ValueOffset, $part[0].Length)
                $url = [System.Text.Encoding]::ASCII.GetString($bytes, $part[1].ValueOffset, $part[1].Length)
                if ($method -eq '2B-06-01-05-05-07-30-01') {
                    $ocsp.Add($url)
                } elseif ($method -eq '2B-06-01-05-05-07-30-02') {
                    $caIssuers.Add($url)
                }
            }
        } catch {
            Write-Verbose "Authority Information Access extension of '$($Certificate.Subject)' could not be decoded: $($_.Exception.Message)"
        }
    }

    [PSCustomObject]@{
        Crl       = $crl.ToArray()
        Ocsp      = $ocsp.ToArray()
        CaIssuers = $caIssuers.ToArray()
    }
}

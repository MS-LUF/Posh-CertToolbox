function Invoke-CertToolboxCertificateUrlTest {
    <#
    .SYNOPSIS
        Tests every CRL, OCSP and issuer-certificate URL found in the certificates of two chains.
    .DESCRIPTION
        Takes the chain a server sent and the chain built locally, and for each distinct
        certificate (matched by thumbprint, so one present in both chains is tested once)
        requests each URL it carries and reads the answer:

        Crl: the CRL is downloaded and read. Result is Revoked when the certificate's serial is
        listed, CrlExpired when it is not listed but the CRL's next update is in the past, and
        NotRevoked otherwise.

        Ocsp: the responder is asked about the certificate. Result is Good, Revoked or Unknown
        as answered, or ResponderError when the responder refuses the request. The issuer's
        certificate is needed to ask; it is looked up in both chains, and the test is Skipped
        when it is in neither.

        CaIssuers: the URL is downloaded. Result is IssuerMatch when it returns a certificate
        whose subject is the certificate's issuer, IssuerMismatch when it returns other
        certificates, and NotACertificate otherwise.

        Any type: Failed when the URL cannot be reached or its content cannot be read, Skipped
        for a URL that is not http or https.

        Each distinct request is made once, even when several certificates share the URL. No
        signature is verified: these tests tell whether the revocation and issuer
        infrastructure answers and what it says, they are not a trust decision.
    .PARAMETER ServerCertificate
        The certificates the server sent, leaf first.
    .PARAMETER LocalCertificate
        The certificates of the locally built chain, leaf first.
    .PARAMETER TimeoutSec
        Time allowed for each request, in seconds.
    .OUTPUTS
        PSCustomObject (type name CertToolbox.CertificateUrlTest), one per certificate and URL.
    .EXAMPLE
        Invoke-CertToolboxCertificateUrlTest -ServerCertificate $sent -LocalCertificate $built
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]] $ServerCertificate,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]] $LocalCertificate,

        [Parameter()]
        [int] $TimeoutSec = 10
    )

    # Distinct certificates, server-sent ones first, each with the chain(s) it belongs to.
    $entry = [ordered]@{}
    foreach ($certificate in $ServerCertificate) {
        if (-not $entry.Contains($certificate.Thumbprint)) {
            $entry[$certificate.Thumbprint] = @{ Certificate = $certificate; Chain = 'Server' }
        }
    }
    foreach ($certificate in $LocalCertificate) {
        if ($entry.Contains($certificate.Thumbprint)) {
            $entry[$certificate.Thumbprint].Chain = 'Both'
        } else {
            $entry[$certificate.Thumbprint] = @{ Certificate = $certificate; Chain = 'Local' }
        }
    }
    $allCertificate = @($entry.Values | ForEach-Object { $_.Certificate })

    # One request per distinct key; its outcome, success or failure, is reused.
    $cache = @{}
    $fetch = {
        param([string] $key, [hashtable] $requestParameter)

        if (-not $cache.ContainsKey($key)) {
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $outcome = @{ Content = $null; Error = $null; ElapsedMs = 0 }
            try {
                $outcome.Content = Invoke-CertToolboxHttpRequest @requestParameter
            } catch {
                $outcome.Error = (Resolve-CertToolboxException -Exception $_.Exception).Message
            }
            $outcome.ElapsedMs = [int]$stopwatch.ElapsedMilliseconds
            $cache[$key] = $outcome
        }
        $cache[$key]
    }

    foreach ($item in $entry.Values) {
        $certificate = $item.Certificate
        $url = Get-CertToolboxCertificateUrl -Certificate $certificate

        $issuerName = [System.Convert]::ToBase64String($certificate.IssuerName.RawData)
        $issuer = $allCertificate |
            Where-Object { [System.Convert]::ToBase64String($_.SubjectName.RawData) -ceq $issuerName } |
            Select-Object -First 1

        $serial = $certificate.GetSerialNumber()
        [System.Array]::Reverse($serial)

        $work = @(
            foreach ($value in $url.Crl) { @{ Type = 'Crl'; Url = $value } }
            foreach ($value in $url.Ocsp) { @{ Type = 'Ocsp'; Url = $value } }
            foreach ($value in $url.CaIssuers) { @{ Type = 'CaIssuers'; Url = $value } }
        )

        foreach ($task in $work) {
            $row = [ordered]@{
                PSTypeName = 'CertToolbox.CertificateUrlTest'
                Subject    = $certificate.Subject
                Thumbprint = $certificate.Thumbprint
                Chain      = $item.Chain
                Type       = $task.Type
                Url        = $task.Url
                Result     = $null
                Reachable  = $null
                ThisUpdate = $null
                NextUpdate = $null
                Detail     = $null
                ElapsedMs  = $null
            }

            $uri = $null
            $isHttp = [System.Uri]::TryCreate($task.Url, [System.UriKind]::Absolute, [ref]$uri) -and
                ($uri.Scheme -eq 'http' -or $uri.Scheme -eq 'https')

            if (-not $isHttp) {
                $row.Result = 'Skipped'
                $row.Detail = 'Only http and https URLs are tested.'
            } elseif ($task.Type -eq 'Ocsp' -and -not $issuer) {
                $row.Result = 'Skipped'
                $row.Detail = 'The issuer certificate, needed to build the request, is in neither chain.'
            } else {
                if ($task.Type -eq 'Ocsp') {
                    $request = ConvertTo-CertToolboxOcspRequest -Certificate $certificate -Issuer $issuer
                    $outcome = & $fetch "POST $($task.Url) $([System.Convert]::ToBase64String($request))" @{
                        Uri         = $uri
                        Method      = 'Post'
                        Body        = $request
                        ContentType = 'application/ocsp-request'
                        TimeoutSec  = $TimeoutSec
                    }
                } else {
                    $outcome = & $fetch "GET $($task.Url)" @{ Uri = $uri; TimeoutSec = $TimeoutSec }
                }

                $row.ElapsedMs = $outcome.ElapsedMs
                if ($outcome.Error) {
                    $row.Result = 'Failed'
                    $row.Reachable = $false
                    $row.Detail = $outcome.Error
                } else {
                    $row.Reachable = $true
                    try {
                        switch ($task.Type) {
                            'Crl' {
                                $crl = Read-CertToolboxCrl -Bytes $outcome.Content -SerialNumber $serial
                                $row.ThisUpdate = $crl.ThisUpdate
                                $row.NextUpdate = $crl.NextUpdate
                                $expired = ($null -ne $crl.NextUpdate -and $crl.NextUpdate -lt [datetime]::UtcNow)
                                $row.Detail = "$($crl.EntryCount) revoked certificate(s) listed"
                                if ($crl.SerialListed) {
                                    $row.Result = 'Revoked'
                                    if ($expired) { $row.Detail += '; the CRL is past its next update' }
                                } elseif ($expired) {
                                    $row.Result = 'CrlExpired'
                                } else {
                                    $row.Result = 'NotRevoked'
                                }
                            }
                            'Ocsp' {
                                $ocsp = ConvertFrom-CertToolboxOcspResponse -Bytes $outcome.Content
                                if ($ocsp.ResponseStatus -eq 'Successful') {
                                    $row.Result = $ocsp.CertificateStatus
                                    $row.ThisUpdate = $ocsp.ThisUpdate
                                    $row.NextUpdate = $ocsp.NextUpdate
                                    $row.Detail = "Response produced at $($ocsp.ProducedAt.ToString('u'))"
                                } else {
                                    $row.Result = 'ResponderError'
                                    $row.Detail = "The responder answered $($ocsp.ResponseStatus)."
                                }
                            }
                            'CaIssuers' {
                                $check = Test-CertToolboxIssuerCertificate -Bytes $outcome.Content -Certificate $certificate
                                if (-not $check.IsCertificate) {
                                    $row.Result = 'NotACertificate'
                                    $row.Detail = "$($outcome.Content.Length) bytes that are not a certificate"
                                } elseif ($check.Match) {
                                    $row.Result = 'IssuerMatch'
                                    $row.Detail = $check.Subject
                                } else {
                                    $row.Result = 'IssuerMismatch'
                                    $row.Detail = "Returned: $($check.Subject)"
                                }
                            }
                        }
                    } catch {
                        $row.Result = 'Failed'
                        $row.Detail = "The answer could not be read: $((Resolve-CertToolboxException -Exception $_.Exception).Message)"
                    }
                }
            }

            [PSCustomObject]$row
        }
    }
}

function Invoke-CertToolboxTlsHandshake {
    <#
    .SYNOPSIS
        Performs a TLS client handshake on a connected stream and captures what was negotiated
        and both views of the certificate chain.
    .DESCRIPTION
        Uses SslStream's synchronous AuthenticateAsClient with a scriptblock as the certificate
        validation callback. Confirmed by direct test under Windows PowerShell 5.1 and
        PowerShell 7 on Windows: with the synchronous call
        the callback runs on the calling thread, so a plain scriptblock works and no compiled
        helper is needed; the handshake is bounded by the socket's own send/receive timeouts.

        The callback never rejects the certificate - this is a diagnostic tool, so a broken
        chain must still be reported rather than abort the connection - and copies out of the
        chain object, while it is still valid:
        - the certificates the server sent (the chain policy's ExtraStore; the full framework
          includes the leaf there, modern runtimes do not, so the leaf is put first and
          de-duplicated here);
        - the chain the local machine built and each element's status;
        - the policy errors the runtime itself concluded.

        Not verified on Linux or macOS.
    .PARAMETER Stream
        A connected stream to the server. It is closed when this function returns or throws.
    .PARAMETER TargetHost
        Name sent as SNI and matched against the certificate.
    .PARAMETER SslProtocol
        Protocol versions to offer. None (the default) lets the operating system choose.
    .PARAMETER CheckRevocation
        Asks the runtime to check certificate revocation while building the local chain.
    .OUTPUTS
        PSCustomObject with the negotiated session values, PolicyErrors, ChainStatus,
        RevocationMode, ServerCertificate (leaf first) and LocalChainElement (Certificate and
        Status per element).
    .EXAMPLE
        Invoke-CertToolboxTlsHandshake -Stream $client.GetStream() -TargetHost 'example.com'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [System.IO.Stream] $Stream,

        [Parameter(Mandatory)]
        [string] $TargetHost,

        [Parameter()]
        [System.Security.Authentication.SslProtocols] $SslProtocol = [System.Security.Authentication.SslProtocols]::None,

        [Parameter()]
        [switch] $CheckRevocation
    )

    $state = @{
        Leaf           = $null
        Sent           = @()
        Element        = @()
        ChainStatus    = @()
        PolicyErrors   = [System.Net.Security.SslPolicyErrors]::None
        RevocationMode = $null
        Error          = $null
    }

    $callback = [System.Net.Security.RemoteCertificateValidationCallback] {
        param($source, $certificate, $chain, $policyErrors)

        # Nothing may escape from here: an exception would surface as a handshake failure and
        # hide the real result. It is recorded and reported after the handshake instead.
        try {
            $null = $source
            $state.PolicyErrors = $policyErrors
            if ($certificate) {
                $state.Leaf = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$certificate.GetRawCertData())
            }
            if ($chain) {
                $state.RevocationMode = $chain.ChainPolicy.RevocationMode.ToString()
                $state.Sent = @(foreach ($extra in $chain.ChainPolicy.ExtraStore) {
                        [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$extra.RawData)
                    })
                $state.Element = @(foreach ($element in $chain.ChainElements) {
                        [PSCustomObject]@{
                            Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$element.Certificate.RawData)
                            Status      = @(foreach ($status in $element.ChainElementStatus) { $status.Status.ToString() })
                        }
                    })
                $state.ChainStatus = @(foreach ($status in $chain.ChainStatus) { $status.Status.ToString() })
            }
        } catch {
            $state.Error = $_.Exception
        }
        $true
    }

    $ssl = [System.Net.Security.SslStream]::new($Stream, $false, $callback)
    try {
        $ssl.AuthenticateAsClient($TargetHost, $null, $SslProtocol, [bool]$CheckRevocation)

        if ($state.Error) {
            Write-Warning "Certificate chain details for '$TargetHost' could not be fully captured: $($state.Error.Message)"
        }

        # Leaf first, then whatever else the server sent, in the order the runtime exposes it.
        $serverCertificate = @()
        if ($state.Leaf) {
            $serverCertificate = @($state.Leaf) + @($state.Sent | Where-Object { $_.Thumbprint -ne $state.Leaf.Thumbprint })
        }

        # The negotiated cipher suite is only exposed by modern runtimes; the full framework has
        # the separate algorithm properties only.
        $cipherSuite = $null
        if ($ssl.PSObject.Properties['NegotiatedCipherSuite']) {
            $cipherSuite = $ssl.NegotiatedCipherSuite.ToString()
        }

        # 44550 (0xAE06, CALG_ECDH_EPHEM) is what both runtimes return for ECDHE; it has no
        # member in ExchangeAlgorithmType, so it would otherwise print as a bare number.
        $keyExchange = $ssl.KeyExchangeAlgorithm.ToString()
        if ([int]$ssl.KeyExchangeAlgorithm -eq 44550) {
            $keyExchange = 'ECDHE'
        }

        [PSCustomObject]@{
            Protocol             = $ssl.SslProtocol.ToString()
            CipherSuite          = $cipherSuite
            CipherAlgorithm      = $ssl.CipherAlgorithm.ToString()
            CipherStrength       = $ssl.CipherStrength
            HashAlgorithm        = $ssl.HashAlgorithm.ToString()
            KeyExchangeAlgorithm = $keyExchange
            PolicyErrors         = $state.PolicyErrors.ToString()
            ChainStatus          = @($state.ChainStatus)
            RevocationMode       = $state.RevocationMode
            ServerCertificate    = @($serverCertificate)
            LocalChainElement    = @($state.Element)
        }
    } finally {
        $ssl.Dispose()
    }
}

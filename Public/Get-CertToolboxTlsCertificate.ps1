function Get-CertToolboxTlsCertificate {
    <#
    .SYNOPSIS
        Connects to a TLS endpoint and reports the negotiated session, the certificate chain the
        server sent, and the chain this machine builds from it.
    .DESCRIPTION
        One connection gives both views of the chain, and three properties comparing them.

        ServerChain holds the certificates the server actually sent, leaf first. This is what
        every client receives, whatever its own stores contain.

        LocalChain holds the chain this machine built to a root, using the server's
        certificates, its own certificate stores and, where the platform does it, downloaded
        intermediates. Each element carries its own Status flags (empty when it has no error).

        MissingIntermediate lists the certificates the local chain needed that the server did
        not send (roots excluded). Clients that cannot find them on their own will fail.

        ServerSentRoot is true when the server sent a self-signed certificate after the leaf,
        which is useless.

        UnusedServerCertificate lists the certificates the server sent that this machine did
        not use.

        The connection is never refused because of the certificate: validation problems are
        reported in ValidationPassed, PolicyError and ChainStatus instead, so that broken
        endpoints can be inspected.

        The handshake is done by the operating system's TLS stack. The protocol versions and
        cipher suites that can be offered therefore depend on the machine this runs on, and
        CipherSuite is only available under PowerShell 7 and later.

        Mail servers that start in plaintext and upgrade to TLS are reached with the StartTls
        parameter: the cmdlet speaks just enough SMTP, IMAP or POP3 to check that the server
        offers the upgrade and to request it, then does the same handshake. Use the Verbose
        switch to see that dialogue.

        With the TestCertificateUrl switch, every CRL, OCSP and issuer-certificate (CA Issuers)
        URL found in the certificates of both chains is requested, and the UrlTest property
        lists one result per certificate and URL: whether it answered, the dates it gave, and
        a Result. For a CRL the Result is NotRevoked, Revoked or CrlExpired; for OCSP it is
        Good, Revoked, Unknown or ResponderError; for CA Issuers it is IssuerMatch,
        IssuerMismatch or NotACertificate; and for any of them Failed (no usable answer) or
        Skipped (not testable, with the reason in Detail).

        These tests show whether the revocation and issuer infrastructure answers and what it
        says. They do not verify the signature of a CRL or of an OCSP response, so they are a
        diagnosis and not a trust decision; CheckRevocation gives the operating system's own
        verdict. They contact the certificate authorities' servers, over plain HTTP as those
        URLs require.
    .PARAMETER HostName
        One or more DNS names or IP addresses to connect to.
    .PARAMETER Port
        TCP port. Defaults to 443, or with StartTls to the protocol's standard port: 25 for
        Smtp, 143 for Imap, 110 for Pop3.
    .PARAMETER TargetHost
        Name sent as SNI and matched against the certificate, when it differs from HostName (for
        example when connecting to an IP address or to one node behind a load balancer).
    .PARAMETER Protocol
        Protocol versions to offer. SystemDefault (the default) lets the operating system
        choose. Use Test-CertToolboxTlsProtocol to probe each version separately.
    .PARAMETER TimeoutSec
        Timeout, in seconds, for the TCP connection and for each step of the handshake.
    .PARAMETER CheckRevocation
        Also checks certificate revocation while building the local chain.
    .PARAMETER StartTls
        The mail protocol to speak in plaintext before upgrading to TLS: Smtp, Imap or Pop3.
        Omit it for a server that expects TLS from the first byte (HTTPS, SMTPS on 465, IMAPS on
        993, POP3S on 995).
    .PARAMETER SmtpEhloName
        The name announced in the SMTP EHLO command, with StartTls Smtp. Defaults to this
        machine's host name; set it when a server rejects or delays that name.
    .PARAMETER TestCertificateUrl
        Also requests every CRL, OCSP and CA Issuers URL found in the certificates of both
        chains, and reports the outcome in the UrlTest property. TimeoutSec applies to each
        request.
    .INPUTS
        System.String. Host names as strings, or objects with HostName, Port, TargetHost and StartTls properties.
    .OUTPUTS
        PSCustomObject (type name CertToolbox.TlsCertificate), one per host.
    .EXAMPLE
        Get-CertToolboxTlsCertificate -HostName 'www.example.com'
    .EXAMPLE
        (Get-CertToolboxTlsCertificate 'www.example.com').ServerChain | Select-Object Subject, Issuer, NotAfter

        Lists the certificates the server sends.
    .EXAMPLE
        Get-CertToolboxTlsCertificate -HostName '192.0.2.10' -TargetHost 'www.example.com' -Port 8443

        Connects to a specific address while presenting www.example.com as the server name.
    .EXAMPLE
        Get-CertToolboxTlsCertificate -HostName 'mail.example.com' -Port 587 -StartTls Smtp -Verbose

        Inspects the certificate of a mail submission server, showing the SMTP dialogue.
    .EXAMPLE
        (Get-CertToolboxTlsCertificate 'www.example.com' -TestCertificateUrl).UrlTest | Format-Table Subject, Chain, Type, Result, NextUpdate, Url

        Tests the CRL, OCSP and CA Issuers URLs of every certificate of both chains.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('ComputerName', 'DnsName')]
        [ValidateNotNullOrEmpty()]
        [string[]] $HostName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1, 65535)]
        [int] $Port = 443,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('ServerName', 'SNI')]
        [string] $TargetHost,

        [Parameter()]
        [ValidateSet('SystemDefault', 'Ssl3', 'Tls', 'Tls11', 'Tls12', 'Tls13')]
        [string[]] $Protocol = @('SystemDefault'),

        [Parameter()]
        [ValidateRange(1, 600)]
        [int] $TimeoutSec = 10,

        [Parameter()]
        [switch] $CheckRevocation,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Smtp', 'Imap', 'Pop3')]
        [string] $StartTls,

        [Parameter()]
        [ValidatePattern('^[A-Za-z0-9.:\[\]-]+$')]
        [string] $SmtpEhloName,

        [Parameter()]
        [switch] $TestCertificateUrl
    )

    begin {
        $config = Read-CertToolboxConfigFile
        Write-CertToolboxLog -Config $config -Level Debug -CmdletName $MyInvocation.MyCommand.Name `
            -Message 'Cmdlet invoked' -BoundParameters $PSBoundParameters

        $sslProtocol = [System.Security.Authentication.SslProtocols]::None
        foreach ($protocolName in $Protocol) {
            if ($protocolName -ne 'SystemDefault') {
                $sslProtocol = $sslProtocol -bor [System.Security.Authentication.SslProtocols]$protocolName
            }
        }
    }

    process {
        foreach ($item in $HostName) {
            $serverName = $TargetHost
            if (-not $serverName) {
                $serverName = $item
            }

            # A separate variable, not $Port itself: with pipeline input the parameter is bound
            # again for each object, and a value assigned to it here must not leak into the next.
            $endpointPort = $Port
            if ($StartTls -and -not $PSBoundParameters.ContainsKey('Port')) {
                $endpointPort = $script:CertToolboxStartTlsDefaultPort[$StartTls]
            }

            $probeParameter = @{
                HostName        = $item
                Port            = $endpointPort
                TargetHost      = $serverName
                SslProtocol     = $sslProtocol
                TimeoutMs       = $TimeoutSec * 1000
                CheckRevocation = $CheckRevocation
            }
            if ($StartTls) {
                $probeParameter.StartTls = $StartTls
                if ($SmtpEhloName) {
                    $probeParameter.SmtpEhloName = $SmtpEhloName
                }
            }

            try {
                Write-Verbose "TLS handshake with ${item}:$endpointPort (server name '$serverName', protocols $sslProtocol, StartTls '$StartTls')."
                $probe = Invoke-CertToolboxTlsProbe @probeParameter

                if (@($probe.StartTlsDialogue).Count -gt 0) {
                    Write-CertToolboxLog -Config $config -Level Debug -CmdletName $MyInvocation.MyCommand.Name `
                        -Target "${item}:$endpointPort" -Message "$StartTls dialogue before TLS: $(@($probe.StartTlsDialogue) -join ' | ')"
                }

                $serverCertificate = @($probe.ServerCertificate)
                $localElement = @($probe.LocalChainElement)
                $localCertificate = @($localElement | ForEach-Object { $_.Certificate })

                $diagnostic = Get-CertToolboxChainDiagnostic -ServerCertificate $serverCertificate -LocalCertificate $localCertificate

                $leaf = $null
                if ($serverCertificate.Count -gt 0) {
                    $leaf = ConvertTo-CertToolboxCertificateInfo -Certificate $serverCertificate[0]
                }

                $policyError = @("$($probe.PolicyErrors)" -split ',\s*' | Where-Object { $_ -and $_ -ne 'None' })

                $summary = "Handshake completed ($($probe.Protocol)); server sent $($serverCertificate.Count) certificate(s), local chain has $($localCertificate.Count)"
                if ($policyError.Count -eq 0) {
                    $summary += '; validation passed.'
                } else {
                    $summary += "; validation failed: $(@($policyError + @($probe.ChainStatus)) -join ', ')."
                }
                Write-CertToolboxLog -Config $config -Level Information -CmdletName $MyInvocation.MyCommand.Name `
                    -Target "${item}:$endpointPort" -Message $summary

                $startTlsValue = $null
                if ($StartTls) {
                    $startTlsValue = $StartTls
                }

                # $null when the tests were not asked for, a list (possibly empty) when they were.
                $urlTest = $null
                if ($TestCertificateUrl) {
                    $urlTest = @(Invoke-CertToolboxCertificateUrlTest -ServerCertificate $serverCertificate `
                            -LocalCertificate $localCertificate -TimeoutSec $TimeoutSec)

                    $healthy = 'NotRevoked', 'Good', 'IssuerMatch', 'Skipped'
                    $problem = @($urlTest | Where-Object { $healthy -notcontains $_.Result })
                    $urlSummary = "Certificate URL tests: $($urlTest.Count) run, $($problem.Count) with a problem"
                    if ($problem.Count -gt 0) {
                        $urlSummary += ': ' + (@($problem | ForEach-Object { "$($_.Type) $($_.Url) -> $($_.Result)" }) -join '; ')
                    }
                    Write-CertToolboxLog -Config $config -Level Information -CmdletName $MyInvocation.MyCommand.Name `
                        -Target "${item}:$endpointPort" -Message "$urlSummary."
                }

                [PSCustomObject]@{
                    PSTypeName              = 'CertToolbox.TlsCertificate'
                    HostName                = $item
                    Port                    = $endpointPort
                    TargetHost              = $serverName
                    StartTls                = $startTlsValue
                    RemoteAddress           = $probe.RemoteAddress
                    Protocol                = $probe.Protocol
                    CipherSuite             = $probe.CipherSuite
                    CipherAlgorithm         = $probe.CipherAlgorithm
                    CipherStrength          = $probe.CipherStrength
                    HashAlgorithm           = $probe.HashAlgorithm
                    KeyExchangeAlgorithm    = $probe.KeyExchangeAlgorithm
                    ValidationPassed        = ($policyError.Count -eq 0)
                    PolicyError             = $policyError
                    ChainStatus             = @($probe.ChainStatus)
                    RevocationMode          = $probe.RevocationMode
                    Certificate             = $leaf
                    ServerChain             = @($serverCertificate | ForEach-Object { ConvertTo-CertToolboxCertificateInfo -Certificate $_ })
                    LocalChain              = @($localElement | ForEach-Object { ConvertTo-CertToolboxCertificateInfo -Certificate $_.Certificate -Status @($_.Status) })
                    MissingIntermediate     = @($diagnostic.MissingIntermediate | ForEach-Object { ConvertTo-CertToolboxCertificateInfo -Certificate $_ })
                    ServerSentRoot          = $diagnostic.ServerSentRoot
                    UnusedServerCertificate = @($diagnostic.UnusedServerCertificate | ForEach-Object { ConvertTo-CertToolboxCertificateInfo -Certificate $_ })
                    UrlTest                 = $urlTest
                    ElapsedMs               = $probe.ElapsedMs
                }
            } catch {
                $exception = Resolve-CertToolboxException -Exception $_.Exception
                Write-CertToolboxLog -Config $config -Level Error -CmdletName $MyInvocation.MyCommand.Name `
                    -Target "${item}:$endpointPort" -Message "Connection or handshake failed: $($exception.GetType().Name): $($exception.Message)"
                $PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]::new(
                        $exception, 'TlsConnectionFailed', [System.Management.Automation.ErrorCategory]::ConnectionError, "${item}:$endpointPort"))
            }
        }
    }
}

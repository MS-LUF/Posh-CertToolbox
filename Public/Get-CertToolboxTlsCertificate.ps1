function Get-CertToolboxTlsCertificate {
    <#
    .SYNOPSIS
        Connects to a TLS endpoint and reports the negotiated session, the certificate chain the
        server sent, and the chain this machine builds from it.
    .DESCRIPTION
        One connection gives both views of the chain, and three properties comparing them.

        ServerChain holds the certificates the server actually sent, leaf first. This is what
        every client receives, whatever its own stores contain.

        On macOS the operating system's TLS stack reports the chain it completed itself, with
        the intermediates it fetched and the root it added, rather than what the server sent.
        ServerChain is therefore read there from a separate, hand-built TLS 1.2 handshake
        opening to the same address, which costs one more connection. ServerChainSource says
        where ServerChain comes from: TlsStack (Windows and Linux), RawHello (macOS), or
        Unavailable. Unavailable happens on macOS when the server only accepts TLS 1.3, which
        encrypts its certificates, or when that extra connection fails; ServerChain is then
        empty, the three comparison properties are null, and a warning says why.

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

        The signature of each CRL and OCSP answer is verified against the certificate's issuer
        and shown in the Signature column: Valid, Invalid, or NotVerified when it could not be
        checked (the reason is in Detail). An OCSP answer must also be about the certificate
        asked for, and may be signed by a responder certificate the issuer delegated to. When
        the signature is Invalid, the Result becomes InvalidSignature, because such an answer
        proves nothing.

        These tests show whether the revocation and issuer infrastructure answers and what it
        says. A valid signature means the answer comes from the issuer found in these chains;
        whether that issuer is itself trusted is not decided here, so this remains a diagnosis
        and CheckRevocation gives the operating system's own verdict. The tests contact the
        certificate authorities' servers, over plain HTTP as those URLs require.

        The default display is a summary of about ten lines, and some of them are computed
        for display and are not property names: Endpoint, Cipher, Chain, and the Subject,
        Issuer and NotAfter of the leaf, which are read from the Certificate property. Pipe
        the result to Format-List with an asterisk to see every property, or to Format-Table
        for one line per result. The certificates of a chain are shown as a table.
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
    .PARAMETER EveryAddress
        Probes every IP address the name resolves to, instead of the first one that answers,
        and returns one result per address; RemoteAddress tells them apart. Use it to find a
        node behind a load-balanced name that serves a different certificate or chain. An
        address that cannot be reached is an error for that address only. The addresses are
        the ones this machine's resolver returns.
    .PARAMETER AddressFamily
        Uses only the IPv4 or only the IPv6 addresses of the name. With EveryAddress it limits
        the addresses probed; without it, it chooses which family to connect over.
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
        (Get-CertToolboxTlsCertificate 'www.example.com' -TestCertificateUrl).UrlTest | Format-Table Subject, Chain, Type, Result, Signature, NextUpdate, Url

        Tests the CRL, OCSP and CA Issuers URLs of every certificate of both chains.
    .EXAMPLE
        Get-CertToolboxTlsCertificate 'www.example.com' -EveryAddress | Group-Object { $_.Certificate.Thumbprint } | Select-Object Count, Name

        Probes every address behind the name and shows whether they all serve the same certificate.
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
        [switch] $TestCertificateUrl,

        [Parameter()]
        [switch] $EveryAddress,

        [Parameter()]
        [ValidateSet('IPv4', 'IPv6')]
        [string] $AddressFamily
    )

    begin {
        $config = Read-CertToolboxConfigFile
        Write-CertToolboxLog -Config $config -Level Debug -CmdletName $MyInvocation.MyCommand.Name `
            -Message 'Cmdlet invoked' -BoundParameters $PSBoundParameters
        $platform = Get-CertToolboxPlatform

        $sslProtocol = [System.Security.Authentication.SslProtocols]::None
        foreach ($protocolName in $Protocol) {
            if ($protocolName -ne 'SystemDefault') {
                $sslProtocol = $sslProtocol -bor [System.Security.Authentication.SslProtocols]$protocolName
            }
        }
    }

    process {
        $targetParameter = @{ HostName = $HostName; EveryAddress = $EveryAddress }
        if ($AddressFamily) {
            $targetParameter.AddressFamily = $AddressFamily
        }

        foreach ($entry in (Get-CertToolboxProbeTarget @targetParameter)) {
            $item = $entry.HostName
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

            $target = "$($entry.Label):$endpointPort"
            if ($entry.Error) {
                Write-CertToolboxLog -Config $config -Level Error -CmdletName $MyInvocation.MyCommand.Name `
                    -Target $target -Message "The name could not be resolved: $($entry.Error.Message)"
                $PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]::new(
                        $entry.Error, 'TlsConnectionFailed', [System.Management.Automation.ErrorCategory]::ConnectionError, $target))
                continue
            }
            if ($entry.Address) {
                $probeParameter.Address = $entry.Address
            }
            if ($AddressFamily) {
                $probeParameter.AddressFamily = $AddressFamily
            }

            try {
                Write-Verbose "TLS handshake with $target (server name '$serverName', protocols $sslProtocol, StartTls '$StartTls')."
                $probe = Invoke-CertToolboxTlsProbe @probeParameter

                if (@($probe.StartTlsDialogue).Count -gt 0) {
                    Write-CertToolboxLog -Config $config -Level Debug -CmdletName $MyInvocation.MyCommand.Name `
                        -Target $target -Message "$StartTls dialogue before TLS: $(@($probe.StartTlsDialogue) -join ' | ')"
                }

                $serverCertificate = @($probe.ServerCertificate)
                $localElement = @($probe.LocalChainElement)
                $localCertificate = @($localElement | ForEach-Object { $_.Certificate })

                $leaf = $null
                if ($serverCertificate.Count -gt 0) {
                    $leaf = ConvertTo-CertToolboxCertificateInfo -Certificate $serverCertificate[0]
                }

                # On macOS the TLS stack reports the chain the system completed (intermediates it
                # fetched, the root it added), not what the server sent. The server's own list is
                # read from a hand-built handshake opening to the same address instead.
                $serverChainSource = 'TlsStack'
                if ($platform -eq 'MacOS') {
                    $wireConnection = @{
                        HostName   = $item
                        Port       = $endpointPort
                        TargetHost = $serverName
                        TimeoutMs  = $TimeoutSec * 1000
                    }
                    if ($StartTls) {
                        $wireConnection.StartTls = $StartTls
                        if ($SmtpEhloName) {
                            $wireConnection.SmtpEhloName = $SmtpEhloName
                        }
                    }
                    [System.Net.IPAddress] $probedAddress = $null
                    if ($probe.RemoteAddress -and [System.Net.IPAddress]::TryParse("$($probe.RemoteAddress)", [ref] $probedAddress)) {
                        $wireConnection.Address = $probedAddress
                    } elseif ($entry.Address) {
                        $wireConnection.Address = $entry.Address
                    }
                    if ($AddressFamily) {
                        $wireConnection.AddressFamily = $AddressFamily
                    }

                    Write-Verbose "Reading the chain $target sends from a hand-built handshake opening."
                    $wire = Get-CertToolboxWireChain -Connection $wireConnection
                    $wireCertificate = @($wire.Certificate)
                    $wireReason = $wire.Reason
                    if (-not $wireReason -and $serverCertificate.Count -gt 0 -and $wireCertificate[0].Thumbprint -ne $serverCertificate[0].Thumbprint) {
                        $wireReason = 'The server sent another certificate to the hand-built handshake opening than to the TLS handshake.'
                    }

                    if ($wireReason) {
                        $serverChainSource = 'Unavailable'
                        $serverCertificate = @()
                        Write-Warning "${target}: the certificate chain the server sent could not be read. $wireReason"
                        Write-CertToolboxLog -Config $config -Level Information -CmdletName $MyInvocation.MyCommand.Name `
                            -Target $target -Message "Server chain unavailable: $wireReason"
                    } else {
                        $serverChainSource = 'RawHello'
                        $serverCertificate = $wireCertificate
                    }
                }

                $diagnostic = $null
                if ($serverChainSource -ne 'Unavailable') {
                    $diagnostic = Get-CertToolboxChainDiagnostic -ServerCertificate $serverCertificate -LocalCertificate $localCertificate
                }

                $policyError = @("$($probe.PolicyErrors)" -split ',\s*' | Where-Object { $_ -and $_ -ne 'None' })

                $summary = "Handshake completed ($($probe.Protocol)); server sent $($serverCertificate.Count) certificate(s), local chain has $($localCertificate.Count)"
                if ($policyError.Count -eq 0) {
                    $summary += '; validation passed.'
                } else {
                    $summary += "; validation failed: $(@($policyError + @($probe.ChainStatus)) -join ', ')."
                }
                Write-CertToolboxLog -Config $config -Level Information -CmdletName $MyInvocation.MyCommand.Name `
                    -Target $target -Message $summary

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
                        -Target $target -Message "$urlSummary."
                }

                $missingIntermediate = $null
                $serverSentRoot = $null
                $unusedServerCertificate = $null
                if ($diagnostic) {
                    $missingIntermediate = @($diagnostic.MissingIntermediate | ForEach-Object { ConvertTo-CertToolboxCertificateInfo -Certificate $_ })
                    $serverSentRoot = $diagnostic.ServerSentRoot
                    $unusedServerCertificate = @($diagnostic.UnusedServerCertificate | ForEach-Object { ConvertTo-CertToolboxCertificateInfo -Certificate $_ })
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
                    ServerChainSource       = $serverChainSource
                    LocalChain              = @($localElement | ForEach-Object { ConvertTo-CertToolboxCertificateInfo -Certificate $_.Certificate -Status @($_.Status) })
                    MissingIntermediate     = $missingIntermediate
                    ServerSentRoot          = $serverSentRoot
                    UnusedServerCertificate = $unusedServerCertificate
                    UrlTest                 = $urlTest
                    ElapsedMs               = $probe.ElapsedMs
                }
            } catch {
                $exception = Resolve-CertToolboxException -Exception $_.Exception
                Write-CertToolboxLog -Config $config -Level Error -CmdletName $MyInvocation.MyCommand.Name `
                    -Target $target -Message "Connection or handshake failed: $($exception.GetType().Name): $($exception.Message)"
                $PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]::new(
                        $exception, 'TlsConnectionFailed', [System.Management.Automation.ErrorCategory]::ConnectionError, $target))
            }
        }
    }
}

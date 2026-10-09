# Shared test fixtures. Dot-source from a BeforeAll block.

function Get-TestCertificateChain {
    <#
    .SYNOPSIS
        Builds an in-memory root -> intermediate -> leaf certificate chain for tests.
    .DESCRIPTION
        Uses CertificateRequest, available on the full framework (4.7.2 and later) and on modern
        runtimes alike, so the same fixture works under Windows PowerShell 5.1 and PowerShell 7
        without touching any certificate store. The leaf has a Subject Alternative Name with two
        DNS names and one IP address. Also returns an unrelated self-signed certificate that has
        no Subject Alternative Name at all.
    #>
    [CmdletBinding()]
    param()

    $sha256 = [System.Security.Cryptography.HashAlgorithmName]::SHA256
    $padding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    $now = [System.DateTimeOffset]::UtcNow

    $rootKey = [System.Security.Cryptography.RSA]::Create(2048)
    $rootRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=CertToolbox Test Root', $rootKey, $sha256, $padding)
    $rootRequest.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
    $root = $rootRequest.CreateSelfSigned($now.AddDays(-2), $now.AddDays(60))

    $intermediateKey = [System.Security.Cryptography.RSA]::Create(2048)
    $intermediateRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=CertToolbox Test Intermediate', $intermediateKey, $sha256, $padding)
    $intermediateRequest.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
    $intermediatePublic = $intermediateRequest.Create($root, $now.AddDays(-1), $now.AddDays(40), [byte[]](1, 2, 3, 4))
    $intermediate = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($intermediatePublic, $intermediateKey)

    $leafKey = [System.Security.Cryptography.RSA]::Create(2048)
    $leafRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=test.example', $leafKey, $sha256, $padding)
    $sanBuilder = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $sanBuilder.AddDnsName('test.example')
    $sanBuilder.AddDnsName('*.test.example')
    $sanBuilder.AddIpAddress([System.Net.IPAddress]::Parse('192.0.2.10'))
    $leafRequest.CertificateExtensions.Add($sanBuilder.Build())
    $leaf = $leafRequest.Create($intermediate, $now.AddDays(-1), $now.AddDays(30), [byte[]](5, 6, 7, 8))

    $otherKey = [System.Security.Cryptography.RSA]::Create(2048)
    $otherRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Unrelated Self Signed', $otherKey, $sha256, $padding)
    $other = $otherRequest.CreateSelfSigned($now.AddDays(-1), $now.AddDays(10))

    # Public-only copies: the fixtures stand for certificates received from a server.
    $publicOnly = {
        param($certificate)
        [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$certificate.RawData)
    }

    [PSCustomObject]@{
        Root         = & $publicOnly $root
        Intermediate = & $publicOnly $intermediate
        Leaf         = & $publicOnly $leaf
        Other        = & $publicOnly $other
    }
}

function ConvertTo-TestDer {
    <#
    .SYNOPSIS
        Encodes one DER element, for building test fixtures independently of the module's own
        encoder.
    #>
    [CmdletBinding()]
    [OutputType([byte[]], [System.Array], [System.Object[]])]
    param(
        [Parameter(Mandatory)]
        [int] $Tag,

        [AllowEmptyCollection()]
        [byte[]] $Content = @()
    )

    $length = $Content.Length
    if ($length -lt 0x80) {
        $header = [byte[]]@($Tag, $length)
    } elseif ($length -lt 0x100) {
        $header = [byte[]]@($Tag, 0x81, $length)
    } elseif ($length -lt 0x10000) {
        $header = [byte[]]@($Tag, 0x82, ($length -shr 8), ($length -band 0xFF))
    } else {
        $header = [byte[]]@($Tag, 0x83, ($length -shr 16), (($length -shr 8) -band 0xFF), ($length -band 0xFF))
    }
    , ([byte[]]($header + $Content))
}

function ConvertTo-TestDerTime {
    <#
    .SYNOPSIS
        Encodes a date as a DER UTCTime, or as a GeneralizedTime with -Generalized.
    #>
    [CmdletBinding()]
    [OutputType([byte[]], [System.Array], [System.Object[]])]
    param(
        [Parameter(Mandatory)]
        [datetime] $Value,

        [switch] $Generalized
    )

    if ($Generalized) {
        ConvertTo-TestDer -Tag 0x18 -Content ([System.Text.Encoding]::ASCII.GetBytes($Value.ToString('yyyyMMddHHmmss') + 'Z'))
    } else {
        ConvertTo-TestDer -Tag 0x17 -Content ([System.Text.Encoding]::ASCII.GetBytes($Value.ToString('yyMMddHHmmss') + 'Z'))
    }
}

function Get-TestCertificateWithUrl {
    <#
    .SYNOPSIS
        Builds an in-memory CA and a leaf certificate carrying the given CRL, OCSP and CA Issuers
        URLs in its CRL Distribution Points and Authority Information Access extensions.
    #>
    [CmdletBinding()]
    param(
        [string[]] $CrlUrl = @(),

        [string[]] $OcspUrl = @(),

        [string[]] $CaIssuersUrl = @(),

        [byte[]] $SerialNumber = @(0x0A, 0x0B, 0x0C, 0x0D)
    )

    $sha256 = [System.Security.Cryptography.HashAlgorithmName]::SHA256
    $padding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    $now = [System.DateTimeOffset]::UtcNow

    $caKey = [System.Security.Cryptography.RSA]::Create(2048)
    $caRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=CertToolbox Url Test CA', $caKey, $sha256, $padding)
    $caRequest.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
    $ca = $caRequest.CreateSelfSigned($now.AddDays(-2), $now.AddDays(60))

    $leafKey = [System.Security.Cryptography.RSA]::Create(2048)
    $leafRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=url.test.example', $leafKey, $sha256, $padding)

    if ($CrlUrl.Count -gt 0) {
        # SEQUENCE OF DistributionPoint { distributionPoint [0] { fullName [0] { URI [6] } } }
        $points = [byte[]]@()
        foreach ($value in $CrlUrl) {
            $uri = ConvertTo-TestDer -Tag 0x86 -Content ([System.Text.Encoding]::ASCII.GetBytes($value))
            $points = [byte[]]($points + (ConvertTo-TestDer -Tag 0x30 -Content (ConvertTo-TestDer -Tag 0xA0 -Content (ConvertTo-TestDer -Tag 0xA0 -Content $uri))))
        }
        $leafRequest.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509Extension]::new(
                '2.5.29.31', (ConvertTo-TestDer -Tag 0x30 -Content $points), $false))
    }

    if ($OcspUrl.Count + $CaIssuersUrl.Count -gt 0) {
        # SEQUENCE OF AccessDescription { accessMethod OID, accessLocation URI [6] }
        $descriptions = [byte[]]@()
        foreach ($pair in @(
                foreach ($value in $OcspUrl) { @{ Last = 0x01; Url = $value } }
                foreach ($value in $CaIssuersUrl) { @{ Last = 0x02; Url = $value } }
            )) {
            $oid = ConvertTo-TestDer -Tag 0x06 -Content ([byte[]](0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, $pair.Last))
            $uri = ConvertTo-TestDer -Tag 0x86 -Content ([System.Text.Encoding]::ASCII.GetBytes($pair.Url))
            $descriptions = [byte[]]($descriptions + (ConvertTo-TestDer -Tag 0x30 -Content ([byte[]]($oid + $uri))))
        }
        $leafRequest.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509Extension]::new(
                '1.3.6.1.5.5.7.1.1', (ConvertTo-TestDer -Tag 0x30 -Content $descriptions), $false))
    }

    $leaf = $leafRequest.Create($ca, $now.AddDays(-1), $now.AddDays(30), $SerialNumber)

    [PSCustomObject]@{
        Issuer = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$ca.RawData)
        Leaf   = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$leaf.RawData)
    }
}

function Get-TestCrl {
    <#
    .SYNOPSIS
        Builds the bytes of a (unsigned, structurally valid) certificate revocation list.
    #>
    [CmdletBinding()]
    [OutputType([byte[]], [System.Array], [System.Object[]])]
    param(
        [datetime] $ThisUpdate = [datetime]::UtcNow.AddDays(-1),

        [Nullable[datetime]] $NextUpdate = [datetime]::UtcNow.AddDays(6),

        # Each serial as its bytes, most significant first.
        [byte[][]] $RevokedSerial = @(),

        # Extra entries with other serials, to make the list long.
        [int] $PaddingEntryCount = 0,

        [switch] $GeneralizedNextUpdate,

        [switch] $WithoutVersion,

        [switch] $AsPem
    )

    $algorithm = ConvertTo-TestDer -Tag 0x30 -Content ([byte[]](0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00))
    $revokedAt = ConvertTo-TestDerTime -Value $ThisUpdate

    $entries = [System.IO.MemoryStream]::new()
    for ($i = 0; $i -lt $PaddingEntryCount; $i++) {
        $serial = [byte[]](0x7F, (($i -shr 16) -band 0xFF), (($i -shr 8) -band 0xFF), ($i -band 0xFF))
        $entry = ConvertTo-TestDer -Tag 0x30 -Content ([byte[]]((ConvertTo-TestDer -Tag 0x02 -Content $serial) + $revokedAt))
        $entries.Write($entry, 0, $entry.Length)
    }
    foreach ($serial in $RevokedSerial) {
        $entry = ConvertTo-TestDer -Tag 0x30 -Content ([byte[]]((ConvertTo-TestDer -Tag 0x02 -Content $serial) + $revokedAt))
        $entries.Write($entry, 0, $entry.Length)
    }

    $tbs = [System.IO.MemoryStream]::new()
    $parts = @()
    if (-not $WithoutVersion) {
        $parts += , (ConvertTo-TestDer -Tag 0x02 -Content ([byte[]]@(1)))
    }
    $parts += , $algorithm
    $parts += , (ConvertTo-TestDer -Tag 0x30)
    $parts += , (ConvertTo-TestDerTime -Value $ThisUpdate)
    if ($null -ne $NextUpdate) {
        $parts += , (ConvertTo-TestDerTime -Value $NextUpdate -Generalized:$GeneralizedNextUpdate)
    }
    if ($entries.Length -gt 0) {
        $parts += , (ConvertTo-TestDer -Tag 0x30 -Content $entries.ToArray())
    }
    foreach ($part in $parts) {
        $tbs.Write($part, 0, $part.Length)
    }

    $signature = ConvertTo-TestDer -Tag 0x03 -Content ([byte[]](0x00, 0x01, 0x02, 0x03))
    $crl = ConvertTo-TestDer -Tag 0x30 -Content ([byte[]]((ConvertTo-TestDer -Tag 0x30 -Content $tbs.ToArray()) + $algorithm + $signature))

    if ($AsPem) {
        $text = "-----BEGIN X509 CRL-----`n" + [System.Convert]::ToBase64String($crl, 'InsertLineBreaks') + "`n-----END X509 CRL-----`n"
        return , ([System.Text.Encoding]::ASCII.GetBytes($text))
    }
    , $crl
}

function Get-TestOcspResponse {
    <#
    .SYNOPSIS
        Builds the bytes of a (unsigned, structurally valid) OCSP response.
    #>
    [CmdletBinding()]
    [OutputType([byte[]], [System.Array], [System.Object[]])]
    param(
        # 0 is successful; anything else is a responder error carrying no data.
        [int] $ResponseStatus = 0,

        [ValidateSet('Good', 'Revoked', 'Unknown')]
        [string] $CertificateStatus = 'Good',

        [datetime] $ProducedAt = [datetime]::UtcNow.AddHours(-2),

        [datetime] $ThisUpdate = [datetime]::UtcNow.AddHours(-3),

        [Nullable[datetime]] $NextUpdate = [datetime]::UtcNow.AddDays(4),

        [switch] $WithVersion
    )

    $status = ConvertTo-TestDer -Tag 0x0A -Content ([byte[]]@($ResponseStatus))
    if ($ResponseStatus -ne 0) {
        return , (ConvertTo-TestDer -Tag 0x30 -Content $status)
    }

    switch ($CertificateStatus) {
        'Good' { $certStatus = ConvertTo-TestDer -Tag 0x80 }
        'Revoked' { $certStatus = ConvertTo-TestDer -Tag 0xA1 -Content (ConvertTo-TestDerTime -Value $ThisUpdate -Generalized) }
        'Unknown' { $certStatus = ConvertTo-TestDer -Tag 0x82 }
    }

    $single = [byte[]]((ConvertTo-TestDer -Tag 0x30) + $certStatus + (ConvertTo-TestDerTime -Value $ThisUpdate -Generalized))
    if ($null -ne $NextUpdate) {
        $single = [byte[]]($single + (ConvertTo-TestDer -Tag 0xA0 -Content (ConvertTo-TestDerTime -Value $NextUpdate -Generalized)))
    }
    $responses = ConvertTo-TestDer -Tag 0x30 -Content (ConvertTo-TestDer -Tag 0x30 -Content $single)

    $tbsContent = [byte[]]@()
    if ($WithVersion) {
        $tbsContent = [byte[]](ConvertTo-TestDer -Tag 0xA0 -Content (ConvertTo-TestDer -Tag 0x02 -Content ([byte[]]@(0))))
    }
    $responderId = ConvertTo-TestDer -Tag 0xA1 -Content (ConvertTo-TestDer -Tag 0x30)
    $tbsContent = [byte[]]($tbsContent + $responderId + (ConvertTo-TestDerTime -Value $ProducedAt -Generalized) + $responses)

    $algorithm = ConvertTo-TestDer -Tag 0x30 -Content ([byte[]](0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00))
    $signature = ConvertTo-TestDer -Tag 0x03 -Content ([byte[]](0x00, 0x01, 0x02, 0x03))
    $basic = ConvertTo-TestDer -Tag 0x30 -Content ([byte[]]((ConvertTo-TestDer -Tag 0x30 -Content $tbsContent) + $algorithm + $signature))

    $basicOid = ConvertTo-TestDer -Tag 0x06 -Content ([byte[]](0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01))
    $responseBytes = ConvertTo-TestDer -Tag 0xA0 -Content (ConvertTo-TestDer -Tag 0x30 -Content ([byte[]]($basicOid + (ConvertTo-TestDer -Tag 0x04 -Content $basic))))
    ConvertTo-TestDer -Tag 0x30 -Content ([byte[]]($status + $responseBytes))
}

function Start-TestHttpServer {
    <#
    .SYNOPSIS
        Starts a real HTTP server on a free loopback port, answering a few fixed paths from a
        background runspace, so that the module's HTTP client can be tested without mocks.
    .DESCRIPTION
        /ok returns five bytes; /echo returns "METHOD|content type|cache-control|" followed by
        the request body; /missing returns 404; /big returns 5000 bytes; /slow answers after
        four seconds.
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test helper bound to the loopback interface.')]
    param()

    $probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $probe.Start()
    $port = $probe.LocalEndpoint.Port
    $probe.Stop()

    $prefix = "http://localhost:$port/"
    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add($prefix)
    $listener.Start()

    $shell = [powershell]::Create()
    $null = $shell.AddScript({
            param($listener)
            while ($listener.IsListening) {
                try { $context = $listener.GetContext() } catch { break }
                $response = $context.Response
                try {
                    switch ($context.Request.Url.AbsolutePath) {
                        '/ok' { $response.OutputStream.Write([byte[]](1, 2, 3, 4, 5), 0, 5) }
                        '/echo' {
                            $body = [System.IO.MemoryStream]::new()
                            $context.Request.InputStream.CopyTo($body)
                            $head = [System.Text.Encoding]::ASCII.GetBytes("$($context.Request.HttpMethod)|$($context.Request.ContentType)|$($context.Request.Headers['Cache-Control'])|")
                            $response.OutputStream.Write($head, 0, $head.Length)
                            $response.OutputStream.Write($body.ToArray(), 0, [int]$body.Length)
                        }
                        '/missing' { $response.StatusCode = 404 }
                        '/big' { $response.OutputStream.Write((New-Object byte[] 5000), 0, 5000) }
                        '/slow' {
                            Start-Sleep -Seconds 4
                            $response.OutputStream.Write([byte[]](1), 0, 1)
                        }
                        default { $response.StatusCode = 400 }
                    }
                } catch {
                    $null = $_
                } finally {
                    try { $response.Close() } catch { $null = $_ }
                }
            }
        }).AddArgument($listener)

    [PSCustomObject]@{
        Prefix   = $prefix
        Listener = $listener
        Shell    = $shell
        Handle   = $shell.BeginInvoke()
    }
}

function Stop-TestHttpServer {
    <#
    .SYNOPSIS
        Stops a server started with Start-TestHttpServer.
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test helper.')]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject] $Server
    )

    try { $Server.Listener.Stop() } catch { $null = $_ }
    try { $Server.Shell.Stop() } catch { $null = $_ }
    $Server.Listener.Close()
    $Server.Shell.Dispose()
}

function Get-TestScriptedConnection {
    <#
    .SYNOPSIS
        Opens a real loopback TCP connection whose server side has already sent a script.
    .DESCRIPTION
        For testing the plaintext exchanges that precede a TLS upgrade against a real socket,
        without threads: these protocols are strictly request and reply, so everything the
        server will ever say can be written to the socket before the client starts reading.
        What the client sent is read back afterwards with Get-TestClientOutput.
    #>
    [CmdletBinding()]
    param(
        [string[]] $ServerLine = @(),

        [int] $TimeoutMs = 3000
    )

    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $client = [System.Net.Sockets.TcpClient]::new([System.Net.Sockets.AddressFamily]::InterNetwork)
    $client.Connect([System.Net.IPAddress]::Loopback, $listener.LocalEndpoint.Port)
    $server = $listener.AcceptTcpClient()
    $client.ReceiveTimeout = $TimeoutMs
    $client.SendTimeout = $TimeoutMs

    if ($ServerLine.Count -gt 0) {
        $bytes = [System.Text.Encoding]::ASCII.GetBytes(($ServerLine -join "`r`n") + "`r`n")
        $server.GetStream().Write($bytes, 0, $bytes.Length)
        $server.GetStream().Flush()
    }

    [PSCustomObject]@{
        Listener = $listener
        Client   = $client
        Server   = $server
        Stream   = $client.GetStream()
    }
}

function Get-TestClientOutput {
    <#
    .SYNOPSIS
        Returns the lines the client side of a scripted connection has sent so far.
    #>
    [CmdletBinding()]
    [OutputType([System.Array])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject] $Connection
    )

    $stream = $Connection.Server.GetStream()
    $buffer = New-Object byte[] 8192
    $text = ''
    # The client's writes are already in the loopback socket's buffer; a short wait covers the
    # hand-over between the two ends.
    Start-Sleep -Milliseconds 100
    while ($Connection.Server.Available -gt 0) {
        $read = $stream.Read($buffer, 0, $buffer.Length)
        $text += [System.Text.Encoding]::ASCII.GetString($buffer, 0, $read)
    }
    , @($text -split "`r`n" | Where-Object { $_ })
}

function Close-TestScriptedConnection {
    <#
    .SYNOPSIS
        Closes both ends of a scripted connection and its listener.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject] $Connection
    )

    $Connection.Client.Close()
    $Connection.Server.Close()
    $Connection.Listener.Stop()
}

function Get-TestTlsProbeResult {
    <#
    .SYNOPSIS
        Builds an object shaped like Invoke-CertToolboxTlsProbe's output, for mocking it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]] $ServerCertificate,

        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]] $LocalCertificate,

        [string] $PolicyErrors = 'None',

        [string[]] $ChainStatus = @(),

        [string] $Protocol = 'Tls13',

        [string[]] $StartTlsDialogue = @()
    )

    [PSCustomObject]@{
        Protocol             = $Protocol
        CipherSuite          = 'TLS_AES_256_GCM_SHA384'
        CipherAlgorithm      = 'Aes256'
        CipherStrength       = 256
        HashAlgorithm        = 'Sha384'
        KeyExchangeAlgorithm = 'None'
        PolicyErrors         = $PolicyErrors
        ChainStatus          = @($ChainStatus)
        RevocationMode       = 'NoCheck'
        ServerCertificate    = @($ServerCertificate)
        LocalChainElement    = @($LocalCertificate | ForEach-Object { [PSCustomObject]@{ Certificate = $_; Status = @() } })
        RemoteAddress        = '192.0.2.10'
        ElapsedMs            = 12
        StartTlsDialogue     = @($StartTlsDialogue)
    }
}

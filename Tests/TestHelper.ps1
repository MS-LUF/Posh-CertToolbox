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

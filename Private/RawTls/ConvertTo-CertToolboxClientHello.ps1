function ConvertTo-CertToolboxClientHello {
    <#
    .SYNOPSIS
        Builds the bytes of a TLS ClientHello, ready to send, offering exactly the given protocol
        version, cipher suites and key-exchange groups.
    .DESCRIPTION
        The message is built by hand so that what is offered does not depend on what the
        operating system's TLS stack has enabled: that is the whole point of the raw probe.

        The hello only has to make the server answer; the handshake is never completed, so no
        key is kept. For TLS 1.3 a key share is required: 32 random bytes are a valid x25519
        public value, so one is sent when x25519 is among the groups, and none otherwise, in
        which case a server that accepts one of the groups answers by asking for a share of it
        (a HelloRetryRequest), which is all the probe needs to know.

        Extensions sent: server name (skipped for an IP address, which is not a valid name
        there), supported groups, point formats, signature algorithms, certificate status
        request (to see whether the server staples an OCSP response), extended master secret
        and renegotiation info; plus supported versions, key share and key exchange modes for
        TLS 1.3. An SSL 3.0 hello carries no extension at all, as that version predates them.
    .PARAMETER Protocol
        The single protocol version to offer.
    .PARAMETER CipherSuite
        The cipher suites to offer, by their IANA number, in order of preference.
    .PARAMETER ServerName
        The server name to send.
    .PARAMETER Group
        The key-exchange groups to offer, by their IANA number.
    .OUTPUTS
        System.Byte[]. One TLS record holding the ClientHello.
    .EXAMPLE
        ConvertTo-CertToolboxClientHello -Protocol Tls12 -CipherSuite 0xC02F, 0xC030 -ServerName 'www.example.com' -Group 29, 23
    #>
    [CmdletBinding()]
    [OutputType([byte[]], [System.Array])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Ssl3', 'Tls', 'Tls11', 'Tls12', 'Tls13')]
        [string] $Protocol,

        [Parameter(Mandatory)]
        [int[]] $CipherSuite,

        [Parameter(Mandatory)]
        [string] $ServerName,

        [Parameter()]
        [AllowEmptyCollection()]
        [int[]] $Group = @()
    )

    # Two helpers kept local: every length and code point in TLS is big-endian.
    $addUInt16 = {
        param($list, [int] $value)
        $list.Add([byte](($value -shr 8) -band 0xFF))
        $list.Add([byte]($value -band 0xFF))
    }
    $addExtension = {
        param($list, [int] $type, $data)
        & $addUInt16 $list $type
        & $addUInt16 $list $data.Count
        $list.AddRange([byte[]]$data.ToArray())
    }

    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $random = New-Object byte[] 32
        $generator.GetBytes($random)
        $sessionId = New-Object byte[] 32
        $generator.GetBytes($sessionId)
        $keyShare = New-Object byte[] 32
        $generator.GetBytes($keyShare)
    } finally {
        $generator.Dispose()
    }

    $body = [System.Collections.Generic.List[byte]]::new()

    # TLS 1.3 announces itself as 1.2 here and gives its real version in an extension.
    $version = [Math]::Min($script:CertToolboxTlsVersionCode[$Protocol], 0x0303)
    & $addUInt16 $body $version
    $body.AddRange($random)

    if ($Protocol -eq 'Tls13') {
        # A non-empty session id is what middleboxes expect to see (RFC 8446, appendix D.4).
        $body.Add(32)
        $body.AddRange($sessionId)
    } else {
        $body.Add(0)
    }

    & $addUInt16 $body ($CipherSuite.Count * 2)
    foreach ($suite in $CipherSuite) {
        & $addUInt16 $body $suite
    }

    # One compression method: none.
    $body.Add(1)
    $body.Add(0)

    if ($Protocol -ne 'Ssl3') {
        $extensions = [System.Collections.Generic.List[byte]]::new()

        $address = $null
        if (-not [System.Net.IPAddress]::TryParse($ServerName, [ref]$address)) {
            $name = [System.Text.Encoding]::ASCII.GetBytes($ServerName)
            $data = [System.Collections.Generic.List[byte]]::new()
            & $addUInt16 $data ($name.Length + 3)
            $data.Add(0)
            & $addUInt16 $data $name.Length
            $data.AddRange($name)
            & $addExtension $extensions 0 $data
        }

        $data = [System.Collections.Generic.List[byte]]::new()
        & $addUInt16 $data ($Group.Count * 2)
        foreach ($item in $Group) {
            & $addUInt16 $data $item
        }
        & $addExtension $extensions 10 $data

        # Point formats: uncompressed only.
        $data = [System.Collections.Generic.List[byte]]::new()
        $data.AddRange([byte[]](1, 0))
        & $addExtension $extensions 11 $data

        # Signature algorithms: ECDSA and RSA (PSS and PKCS #1) with SHA-256/384/512, Ed25519,
        # then the SHA-1 forms that only old servers still need.
        $algorithms = [byte[]](
            0x04, 0x03, 0x05, 0x03, 0x06, 0x03,
            0x08, 0x07,
            0x08, 0x04, 0x08, 0x05, 0x08, 0x06,
            0x08, 0x09, 0x08, 0x0A, 0x08, 0x0B,
            0x04, 0x01, 0x05, 0x01, 0x06, 0x01,
            0x02, 0x03, 0x02, 0x01, 0x02, 0x02)
        $data = [System.Collections.Generic.List[byte]]::new()
        & $addUInt16 $data $algorithms.Length
        $data.AddRange($algorithms)
        & $addExtension $extensions 13 $data

        # Certificate status request: OCSP, no responder list, no extensions.
        $data = [System.Collections.Generic.List[byte]]::new()
        $data.AddRange([byte[]](1, 0, 0, 0, 0))
        & $addExtension $extensions 5 $data

        # Extended master secret: empty.
        & $addExtension $extensions 23 ([System.Collections.Generic.List[byte]]::new())

        # Renegotiation info: an empty value, for an initial handshake.
        $data = [System.Collections.Generic.List[byte]]::new()
        $data.Add(0)
        & $addExtension $extensions 0xFF01 $data

        if ($Protocol -eq 'Tls13') {
            # Supported versions: TLS 1.3 and nothing else.
            $data = [System.Collections.Generic.List[byte]]::new()
            $data.AddRange([byte[]](2, 3, 4))
            & $addExtension $extensions 43 $data

            # Key exchange modes: (EC)DHE.
            $data = [System.Collections.Generic.List[byte]]::new()
            $data.AddRange([byte[]](1, 1))
            & $addExtension $extensions 45 $data

            $shares = [System.Collections.Generic.List[byte]]::new()
            if ($Group -contains 29) {
                & $addUInt16 $shares 29
                & $addUInt16 $shares $keyShare.Length
                $shares.AddRange($keyShare)
            }
            $data = [System.Collections.Generic.List[byte]]::new()
            & $addUInt16 $data $shares.Count
            $data.AddRange($shares)
            & $addExtension $extensions 51 $data
        }

        & $addUInt16 $body $extensions.Count
        $body.AddRange($extensions)
    }

    $record = [System.Collections.Generic.List[byte]]::new()
    # Record: handshake (22), a record version old enough for any server, then the length.
    $record.Add(22)
    if ($Protocol -eq 'Ssl3') {
        & $addUInt16 $record 0x0300
    } else {
        & $addUInt16 $record 0x0301
    }
    & $addUInt16 $record ($body.Count + 4)
    # Handshake message: client_hello (1) and a three-byte length.
    $record.Add(1)
    $record.Add([byte](($body.Count -shr 16) -band 0xFF))
    & $addUInt16 $record ($body.Count -band 0xFFFF)
    $record.AddRange($body)

    , $record.ToArray()
}

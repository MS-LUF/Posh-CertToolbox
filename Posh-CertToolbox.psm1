$script:ModuleRoot = $PSScriptRoot

# Debug < Information < Warning < Error - used by Write-CertToolboxLog to compare an entry's
# Level against the configured MinimumLevel.
$script:LogLevelSeverity = @{
    Debug       = 0
    Information = 1
    Warning     = 2
    Error       = 3
}

# "Warn once per session" flags for config/logging failures - see Read-CertToolboxConfigFile,
# Get-CertToolboxLoggingConfig and Write-CertToolboxLog / Write-CertToolboxFileLogEntry /
# Write-CertToolboxEventLogEntry.
$script:LoggingConfigWarned = $false
$script:LoggingSinkFailed = $false

# Google's DNS-over-HTTPS JSON API - the single DNS transport this module uses. Defined once
# here so Invoke-CertToolboxDnsQuery and its tests share the same value.
$script:CertToolboxDnsEndpoint = 'https://dns.google/resolve'

# DNS resource record type number for CAA (RFC 8659) - used to keep only CAA answers when a
# response also carries the CNAME records that led to them.
$script:CertToolboxCaaRecordType = 257

# Port used when a StartTls protocol is requested without an explicit -Port: the protocol's
# standard plaintext port, since the cmdlets' general default (443) is never right for these.
$script:CertToolboxStartTlsDefaultPort = @{
    Smtp = 25
    Imap = 143
    Pop3 = 110
}

# Upper bound on the lines of one plaintext reply read before a TLS upgrade, so a misbehaving
# server cannot keep a STARTTLS exchange reading forever.
$script:CertToolboxStartTlsMaxReplyLine = 200

# Largest CRL, OCSP response or issuer certificate downloaded by the certificate URL tests. CRLs
# of a few megabytes are common; this stops one oversized file from stalling a batch.
$script:CertToolboxMaxDownloadBytes = 20MB

# Signature algorithms Test-CertToolboxSignature can verify, keyed by the algorithm's object
# identifier as dash-separated hex bytes (the form the DER readers of this module produce).
# 2A-86-48-86-F7-0D-01-01-xx is 1.2.840.113549.1.1.x (RSA with PKCS #1 v1.5 padding) and
# 2A-86-48-CE-3D-04-xx is 1.2.840.10045.4.x (ECDSA).
$script:CertToolboxSignatureAlgorithm = @{
    '2A-86-48-86-F7-0D-01-01-05' = @{ Key = 'RSA'; Hash = 'SHA1' }
    '2A-86-48-86-F7-0D-01-01-0B' = @{ Key = 'RSA'; Hash = 'SHA256' }
    '2A-86-48-86-F7-0D-01-01-0C' = @{ Key = 'RSA'; Hash = 'SHA384' }
    '2A-86-48-86-F7-0D-01-01-0D' = @{ Key = 'RSA'; Hash = 'SHA512' }
    '2A-86-48-CE-3D-04-01'       = @{ Key = 'ECDSA'; Hash = 'SHA1' }
    '2A-86-48-CE-3D-04-03-02'    = @{ Key = 'ECDSA'; Hash = 'SHA256' }
    '2A-86-48-CE-3D-04-03-03'    = @{ Key = 'ECDSA'; Hash = 'SHA384' }
    '2A-86-48-CE-3D-04-03-04'    = @{ Key = 'ECDSA'; Hash = 'SHA512' }
}

# Names for the algorithms that are recognised but not verified, so the reason given to the
# user reads better than a string of hex bytes.
$script:CertToolboxUnsupportedSignatureAlgorithm = @{
    '2A-86-48-86-F7-0D-01-01-0A' = 'RSASSA-PSS'
    '2B-65-70'                   = 'Ed25519'
    '2B-65-71'                   = 'Ed448'
}

# --- Raw TLS probe (Get-CertToolboxTlsCapability) ---

# Protocol versions as they appear on the wire.
$script:CertToolboxTlsVersionCode = @{
    Ssl3  = 0x0300
    Tls   = 0x0301
    Tls11 = 0x0302
    Tls12 = 0x0303
    Tls13 = 0x0304
}

# Every cipher suite of the IANA TLS registry, loaded from Data/TlsCipherSuite.csv (generated
# from https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv, signalling values
# and unassigned ranges left out). Offering all of them is what lets the probe find the suites
# an audit cares about: NULL, EXPORT, anonymous, RC4, DES.
$script:CertToolboxCipherSuiteName = @{}
foreach ($row in Import-Csv -Path (Join-Path (Join-Path $script:ModuleRoot 'Data') 'TlsCipherSuite.csv')) {
    $script:CertToolboxCipherSuiteName[[int]$row.Code] = $row.Name
}

# A TLS 1.3 suite names only a cipher and a hash, so its name has no "_WITH_"; every suite of
# the earlier versions has it. The two sets are never offered together.
$script:CertToolboxLegacyCipherSuite = [int[]]@($script:CertToolboxCipherSuiteName.Keys |
        Where-Object { $script:CertToolboxCipherSuiteName[$_] -match '_WITH_' } | Sort-Object)
$script:CertToolboxTls13CipherSuite = [int[]]@($script:CertToolboxCipherSuiteName.Keys |
        Where-Object { $script:CertToolboxCipherSuiteName[$_] -notmatch '_WITH_' } | Sort-Object)

# Key-exchange groups by their IANA number, for display.
$script:CertToolboxTlsGroupName = @{
    19   = 'secp192r1'
    21   = 'secp224r1'
    22   = 'secp256k1'
    23   = 'secp256r1'
    24   = 'secp384r1'
    25   = 'secp521r1'
    26   = 'brainpoolP256r1'
    27   = 'brainpoolP384r1'
    28   = 'brainpoolP512r1'
    29   = 'x25519'
    30   = 'x448'
    31   = 'brainpoolP256r1tls13'
    32   = 'brainpoolP384r1tls13'
    33   = 'brainpoolP512r1tls13'
    256  = 'ffdhe2048'
    257  = 'ffdhe3072'
    258  = 'ffdhe4096'
    259  = 'ffdhe6144'
    260  = 'ffdhe8192'
    4587 = 'SecP256r1MLKEM768'
    4588 = 'X25519MLKEM768'
    4589 = 'SecP384r1MLKEM1024'
}

# Groups offered when looking for the ones a server accepts. TLS 1.3 costs one connection per
# group, so that list is kept to the groups in real use.
$script:CertToolboxTls13ProbeGroup = [int[]](29, 23, 24, 25, 30, 256, 257, 258, 4588, 4587, 4589)
$script:CertToolboxLegacyProbeGroup = [int[]](29, 23, 24, 25, 30, 26, 27, 28, 22, 21, 19)

# TLS alert descriptions (RFC 8446, section 6), for reporting why a server refused.
$script:CertToolboxTlsAlertName = @{
    0   = 'close_notify'
    10  = 'unexpected_message'
    20  = 'bad_record_mac'
    22  = 'record_overflow'
    40  = 'handshake_failure'
    42  = 'bad_certificate'
    43  = 'unsupported_certificate'
    47  = 'illegal_parameter'
    48  = 'unknown_ca'
    49  = 'access_denied'
    50  = 'decode_error'
    51  = 'decrypt_error'
    70  = 'protocol_version'
    71  = 'insufficient_security'
    80  = 'internal_error'
    86  = 'inappropriate_fallback'
    90  = 'user_canceled'
    109 = 'missing_extension'
    110 = 'unsupported_extension'
    112 = 'unrecognized_name'
    113 = 'bad_certificate_status_response'
    115 = 'unknown_psk_identity'
    116 = 'certificate_required'
    120 = 'no_application_protocol'
}

foreach ($layer in Get-ChildItem -Path (Join-Path $script:ModuleRoot 'Private') -Filter '*.ps1' -Recurse -File -ErrorAction SilentlyContinue) {
    . $layer.FullName
}

foreach ($cmdlet in Get-ChildItem -Path (Join-Path $script:ModuleRoot 'Public') -Filter '*.ps1' -File -ErrorAction SilentlyContinue) {
    . $cmdlet.FullName
}

Export-ModuleMember -Function @(
    'Get-CertToolboxCaaRecord',
    'Get-CertToolboxTlsCapability',
    'Get-CertToolboxTlsCertificate',
    'Test-CertToolboxTlsProtocol'
)

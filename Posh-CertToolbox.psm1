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

foreach ($layer in Get-ChildItem -Path (Join-Path $script:ModuleRoot 'Private') -Filter '*.ps1' -Recurse -File -ErrorAction SilentlyContinue) {
    . $layer.FullName
}

foreach ($cmdlet in Get-ChildItem -Path (Join-Path $script:ModuleRoot 'Public') -Filter '*.ps1' -File -ErrorAction SilentlyContinue) {
    . $cmdlet.FullName
}

Export-ModuleMember -Function @(
    'Get-CertToolboxCaaRecord',
    'Get-CertToolboxTlsCertificate',
    'Test-CertToolboxTlsProtocol'
)

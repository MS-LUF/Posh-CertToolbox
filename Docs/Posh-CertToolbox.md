---
Module Name: Posh-CertToolbox
Module Guid: b7e4c1a2-5f3d-4e8a-9c6b-2d1f0a7e8c34
Download Help Link:
Help Version: 0.9.1.0
Locale: en-US
---

# Posh-CertToolbox Module
## Description
Troubleshoot TLS and certificates: inspect an endpoint and its certificate chain, scan the versions and cipher suites a server supports, read DNS CAA records.

## Posh-CertToolbox Cmdlets
### [Get-CertToolboxCaaRecord](Get-CertToolboxCaaRecord.md)
Gets the DNS CAA records that apply to a domain, telling which CAs may issue for it.

### [Get-CertToolboxTlsCapability](Get-CertToolboxTlsCapability.md)
Finds what a TLS server supports: protocol versions, cipher suites, key-exchange groups and a few handshake features.

### [Get-CertToolboxTlsCertificate](Get-CertToolboxTlsCertificate.md)
Connects to a TLS endpoint and reports the negotiated session, the certificate chain the server sent, and the chain this machine builds from it.

### [Test-CertToolboxTlsProtocol](Test-CertToolboxTlsProtocol.md)
Probes a TLS endpoint once per protocol version and reports which ones could be negotiated.

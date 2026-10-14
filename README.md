# Posh-CertToolbox

A PowerShell toolbox to troubleshoot TLS and certificates. No dependencies: it runs on Windows PowerShell 5.1 and on PowerShell 7 (Windows, Linux, macOS) with nothing else to install.

## Cmdlets

| Cmdlet | What it tells you |
|---|---|
| `Get-CertToolboxTlsCertificate` | What was negotiated with an endpoint, the certificate chain the server **sent**, the chain this machine **built** from it, and how they differ |
| `Get-CertToolboxTlsCapability` | What the **server** supports: TLS versions, every cipher suite in its order, key-exchange groups, OCSP stapling |
| `Test-CertToolboxTlsProtocol` | Which TLS versions (SSL 3.0 to TLS 1.3) **this machine** can negotiate with an endpoint |
| `Get-CertToolboxCaaRecord` | Which CAs the DNS CAA records allow to issue for a domain |

The three TLS cmdlets also reach mail servers that upgrade from plaintext, with `-StartTls Smtp`, `Imap` or `Pop3`, and probe every IP address behind a name with `-EveryAddress`. `Get-CertToolboxTlsCertificate -TestCertificateUrl` also tests the CRL, OCSP and issuer URLs of every certificate of both chains.

## Install

Not published to the PowerShell Gallery yet. Clone the repository and import the manifest:

```powershell
Import-Module .\Posh-CertToolbox.psd1
```

## Quick start

```powershell
# Session, leaf certificate and both chain views
$r = Get-CertToolboxTlsCertificate www.example.com
$r.ServerChain | Format-Table Subject, Issuer      # what the server sends
$r.LocalChain  | Format-Table Subject, Issuer      # what this machine builds
$r.MissingIntermediate                             # needed, but not sent by the server

# What the server supports: versions, then weak cipher suites
$c = Get-CertToolboxTlsCapability www.example.com
$c.Protocol | Format-Table Protocol, Accepted, CipherSuiteCount, Reason
$c.CipherSuite | Where-Object Weak

# What this machine can negotiate
Test-CertToolboxTlsProtocol www.example.com | Format-Table Protocol, Negotiated, ErrorMessage

# A mail server, upgrading with STARTTLS
Get-CertToolboxTlsCertificate mail.example.com -Port 587 -StartTls Smtp

# CRL, OCSP and issuer URLs of every certificate of both chains
(Get-CertToolboxTlsCertificate www.example.com -TestCertificateUrl).UrlTest | Format-Table Chain, Type, Result, Url

# Every node behind a name: do they all serve the same certificate?
Get-CertToolboxTlsCertificate www.example.com -EveryAddress | Group-Object { $_.Certificate.Thumbprint }

# CAs allowed to issue
Get-CertToolboxCaaRecord www.example.com
```

[HowTo.md](HowTo.md) has a task-by-task walkthrough with real output. The parameter reference is in [Docs/](Docs/) and in `Get-Help <cmdlet> -Full`.

## Good to know

- **What is displayed is a summary.** Results print in a few lines; the objects hold much more, shown with `Format-List *`. Lines such as `Endpoint` or `Subject` are computed for display and are not property names.
- **An invalid certificate never fails the call.** It is reported in `ValidationPassed`, `PolicyError` and `ChainStatus`, so broken endpoints can be inspected.
- **Two views of TLS versions.** `Test-CertToolboxTlsProtocol` uses the operating system's TLS stack, so a failure may be your machine's; `Get-CertToolboxTlsCapability` sends its own handshakes and reports the server's answer.
- **`Get-CertToolboxTlsCapability` makes many connections**, typically 20 to 60 per host, each seen by the server as an abandoned handshake. `-Protocol` narrows the scan.
- **`CipherSuite` needs PowerShell 7.** Windows PowerShell 5.1 reports the cipher algorithm and strength only.
- **`-TestCertificateUrl` diagnoses, it does not decide trust.** It verifies that each CRL and OCSP answer is signed by the certificate's issuer, not that the issuer is trusted; `-CheckRevocation` gives the operating system's verdict.
- **CAA lookups go through Google DNS-over-HTTPS** (`dns.google`): the names you query are sent to that service.
- **Logging is off by default.** Copy `Config\Posh-CertToolbox.sample.json` to `$home\Posh-CertToolbox\Posh-CertToolbox-Config.json` and set `Logging.Enabled` to turn it on.
- **Tested on Windows** (Windows PowerShell 5.1 and PowerShell 7) **and on Linux and macOS** (PowerShell 7).

## Tests

```powershell
Invoke-Pester -Path .\Tests -ExcludeTagFilter Integration   # offline
Invoke-Pester -Path .\Tests                                 # also real endpoints
```

## Change log

- **0.9.0** — Short default display for every result; the objects are unchanged.
- **0.8.0** — `-EveryAddress` and `-AddressFamily` on the three TLS cmdlets.
- **0.7.0** — `Get-CertToolboxTlsCapability`: versions, cipher suites and groups a server supports.
- **0.6.1** — Fix: `PublicKeySize` was empty on Linux.
- **0.6.0** — CRL and OCSP signatures are verified by the URL tests.
- **0.5.0** — CRL, OCSP and CA Issuers URL tests on both chains (`-TestCertificateUrl`).
- **0.4.0** — README, HowTo and generated help files.
- **0.3.0** — STARTTLS for SMTP, IMAP and POP3.
- **0.2.0** — Opt-in logging, driven by a JSON config file.
- **0.1.0** — `Get-CertToolboxTlsCertificate`, `Test-CertToolboxTlsProtocol`, `Get-CertToolboxCaaRecord`.

## License

[Artistic Licence 2.0](https://opensource.org/licenses/artistic-license-2.0).

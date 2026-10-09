# Posh-CertToolbox

A PowerShell toolbox to troubleshoot TLS and certificates. No dependencies: it runs on Windows PowerShell 5.1 and on PowerShell 7 (Windows, Linux, macOS) with nothing else to install.

## Cmdlets

| Cmdlet | What it tells you |
|---|---|
| `Get-CertToolboxTlsCertificate` | What was negotiated with an endpoint, the certificate chain the server **sent**, the chain this machine **built** from it, and how they differ |
| `Test-CertToolboxTlsProtocol` | Which TLS versions (SSL 3.0 to TLS 1.3) can be negotiated with an endpoint |
| `Get-CertToolboxCaaRecord` | Which CAs the DNS CAA records allow to issue for a domain |

Both TLS cmdlets also reach mail servers that upgrade from plaintext, with `-StartTls Smtp`, `Imap` or `Pop3`. `Get-CertToolboxTlsCertificate -TestCertificateUrl` also tests the CRL, OCSP and issuer URLs of every certificate of both chains.

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

# TLS versions
Test-CertToolboxTlsProtocol www.example.com | Format-Table Protocol, Negotiated, ErrorMessage

# A mail server, upgrading with STARTTLS
Get-CertToolboxTlsCertificate mail.example.com -Port 587 -StartTls Smtp

# CRL, OCSP and issuer URLs of every certificate of both chains
(Get-CertToolboxTlsCertificate www.example.com -TestCertificateUrl).UrlTest | Format-Table Chain, Type, Result, Url

# CAs allowed to issue
Get-CertToolboxCaaRecord www.example.com
```

[HowTo.md](HowTo.md) has a task-by-task walkthrough with real output. The parameter reference is in [Docs/](Docs/) and in `Get-Help <cmdlet> -Full`.

## Good to know

- **An invalid certificate never fails the call.** It is reported in `ValidationPassed`, `PolicyError` and `ChainStatus`, so broken endpoints can be inspected.
- **The handshake is done by the operating system's TLS stack.** A version that could not be negotiated may be disabled on your machine rather than on the server; `ErrorMessage` tells the two apart.
- **`CipherSuite` needs PowerShell 7.** Windows PowerShell 5.1 reports the cipher algorithm and strength only.
- **`-TestCertificateUrl` diagnoses, it does not decide trust.** It reads CRLs and OCSP answers without verifying their signatures; `-CheckRevocation` gives the operating system's verdict.
- **CAA lookups go through Google DNS-over-HTTPS** (`dns.google`): the names you query are sent to that service.
- **Logging is off by default.** Copy `Config\Posh-CertToolbox.sample.json` to `$home\Posh-CertToolbox\Posh-CertToolbox-Config.json` and set `Logging.Enabled` to turn it on.
- **Tested on Windows** (Windows PowerShell 5.1 and PowerShell 7) **and on Linux and macOS** (PowerShell 7).

## Tests

```powershell
Invoke-Pester -Path .\Tests -ExcludeTagFilter Integration   # offline
Invoke-Pester -Path .\Tests                                 # also real endpoints
```

## Change log

- **0.5.0** — CRL, OCSP and CA Issuers URL tests on both chains (`-TestCertificateUrl`).
- **0.4.0** — README, HowTo and generated help files.
- **0.3.0** — STARTTLS for SMTP, IMAP and POP3.
- **0.2.0** — Opt-in logging, driven by a JSON config file.
- **0.1.0** — `Get-CertToolboxTlsCertificate`, `Test-CertToolboxTlsProtocol`, `Get-CertToolboxCaaRecord`.

## License

[Artistic Licence 2.0](https://opensource.org/licenses/artistic-license-2.0).

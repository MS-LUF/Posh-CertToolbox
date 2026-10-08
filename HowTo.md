# HowTo — Posh-CertToolbox

A task-oriented walkthrough. Every command below was run against the module, under PowerShell 7
on Windows, and the output shown is what came back (trimmed where long). Dates, addresses and
certificates will differ when you run them.

1. [Inspecting a TLS endpoint](#1-inspecting-a-tls-endpoint)
2. [Comparing what the server sends with what your machine builds](#2-comparing-what-the-server-sends-with-what-your-machine-builds)
3. [Reading validation failures](#3-reading-validation-failures)
4. [Testing one node, or a name that does not resolve yet](#4-testing-one-node-or-a-name-that-does-not-resolve-yet)
5. [Checking revocation](#5-checking-revocation)
6. [Saving the certificates to files](#6-saving-the-certificates-to-files)
7. [Finding which TLS versions an endpoint accepts](#7-finding-which-tls-versions-an-endpoint-accepts)
8. [Mail servers: SMTP, IMAP and POP3 with STARTTLS](#8-mail-servers-smtp-imap-and-pop3-with-starttls)
9. [Finding which CAs may issue for a domain](#9-finding-which-cas-may-issue-for-a-domain)
10. [Checking many endpoints at once](#10-checking-many-endpoints-at-once)
11. [Enabling logging](#11-enabling-logging)

```powershell
Import-Module .\Posh-CertToolbox.psd1
```

---

## 1. Inspecting a TLS endpoint

```powershell
$r = Get-CertToolboxTlsCertificate -HostName 'www.google.com'
$r | Format-List HostName, Port, RemoteAddress, Protocol, CipherSuite, ValidationPassed, ElapsedMs
```

```
HostName         : www.google.com
Port             : 443
RemoteAddress    : 142.251.152.119
Protocol         : Tls13
CipherSuite      : TLS_AES_256_GCM_SHA384
ValidationPassed : True
ElapsedMs        : 154
```

The result carries nested certificate objects, so displaying it whole is long; pick the
properties you need. The leaf certificate is in `Certificate`:

```powershell
$r.Certificate | Format-List Subject, Issuer, NotAfter, DaysUntilExpiry, SubjectAlternativeName, PublicKeyAlgorithm, PublicKeySize, SignatureAlgorithm
```

```
Subject                : CN=www.google.com
Issuer                 : CN=WE2, O=Google Trust Services, C=US
NotAfter               : 12/11/2026 9:02:32 PM
DaysUntilExpiry        : 63
SubjectAlternativeName : {www.google.com}
PublicKeyAlgorithm     : ECC
PublicKeySize          : 256
SignatureAlgorithm     : sha256ECDSA
```

Every certificate object also keeps the original `X509Certificate2` in its own `Certificate`
property, for anything not exposed directly (`$r.Certificate.Certificate.Extensions`, for
instance).

`CipherSuite` is empty under Windows PowerShell 5.1, which does not expose it; `CipherAlgorithm`
and `CipherStrength` are filled on both.

---

## 2. Comparing what the server sends with what your machine builds

A server is supposed to send its leaf certificate and every intermediate up to, but not
including, the root. When it does not, some clients still succeed because they find the missing
certificate in their own store or download it, and others fail. One call shows both sides:

```powershell
$r = Get-CertToolboxTlsCertificate 'incomplete-chain.badssl.com'
$r.ServerChain | Format-Table Subject, Issuer
$r.LocalChain  | Format-Table Subject, Issuer, IsSelfSigned
$r.MissingIntermediate | Format-Table Subject
```

```
ServerChain:
Subject         Issuer
-------         ------
CN=*.badssl.com CN=YR1, O=Let's Encrypt, C=US

LocalChain:
Subject                                                   Issuer                                                    IsSelfSigned
-------                                                   ------                                                    ------------
CN=*.badssl.com                                           CN=YR1, O=Let's Encrypt, C=US                                    False
CN=YR1, O=Let's Encrypt, C=US                             CN=Root YR, O=ISRG, C=US                                         False
CN=Root YR, O=ISRG, C=US                                  CN=ISRG Root X1, O=Internet Security Research Group, C=US        False
CN=ISRG Root X1, O=Internet Security Research Group, C=US CN=ISRG Root X1, O=Internet Security Research Group, C=US         True

MissingIntermediate:
Subject
-------
CN=YR1, O=Let's Encrypt, C=US
CN=Root YR, O=ISRG, C=US
```

The server sent one certificate; this machine completed the chain on its own, and validation
passed here. `MissingIntermediate` names the two certificates the server should be sending. A
client that cannot fetch them will reject this server.

Three properties summarise the comparison:

| Property | Meaning |
|---|---|
| `MissingIntermediate` | Certificates the local chain needed, other than the root, that the server did not send |
| `ServerSentRoot` | The server sent a self-signed certificate after the leaf: harmless, but useless |
| `UnusedServerCertificate` | Certificates the server sent that this machine did not use |

`UnusedServerCertificate` typically shows a cross-signed certificate bypassed because the local
store already trusts a newer root:

```powershell
(Get-CertToolboxTlsCertificate 'expired.badssl.com').UnusedServerCertificate | Format-Table Subject, Issuer
```

```
Subject                                                                                           Issuer
-------                                                                                           ------
CN=COMODO RSA Certification Authority, O=COMODO CA Limited, L=Salford, S=Greater Manchester, C=GB CN=AddTrust External CA Root, OU=AddTrust External TTP Network, O=AddTrust AB, C=SE
```

The local chain depends on the machine's stores, so the same server can give different
`LocalChain` and `MissingIntermediate` results from two machines. `ServerChain` does not.

---

## 3. Reading validation failures

An invalid certificate does not fail the call. The connection is completed and the problem is
reported:

```powershell
'expired.badssl.com', 'wrong.host.badssl.com', 'self-signed.badssl.com', 'untrusted-root.badssl.com' |
    Get-CertToolboxTlsCertificate |
    Format-Table HostName, ValidationPassed, @{ n = 'PolicyError'; e = { $_.PolicyError -join ',' } }, @{ n = 'ChainStatus'; e = { $_.ChainStatus -join ',' } }
```

```
HostName                  ValidationPassed PolicyError                   ChainStatus
--------                  ---------------- -----------                   -----------
expired.badssl.com                   False RemoteCertificateChainErrors  NotTimeValid
wrong.host.badssl.com                False RemoteCertificateNameMismatch
self-signed.badssl.com               False RemoteCertificateChainErrors  UntrustedRoot
untrusted-root.badssl.com            False RemoteCertificateChainErrors  UntrustedRoot
```

- `PolicyError` is the overall verdict: a name mismatch, a chain problem, or both.
- `ChainStatus` says what is wrong with the chain.
- Each element of `LocalChain` has its own `Status`, which tells you *which* certificate has the
  problem:

```powershell
(Get-CertToolboxTlsCertificate 'expired.badssl.com').LocalChain |
    Format-Table Subject, NotAfter, @{ n = 'Status'; e = { $_.Status -join ',' } }
```

```
Subject                                                                                                      NotAfter              Status
-------                                                                                                      --------              ------
CN=*.badssl.com, OU=PositiveSSL Wildcard, OU=Domain Control Validated                                        4/13/2015 1:59:59 AM  NotTimeValid
CN=COMODO RSA Domain Validation Secure Server CA, O=COMODO CA Limited, L=Salford, S=Greater Manchester, C=GB 2/12/2029 12:59:59 AM
CN=COMODO RSA Certification Authority, O=COMODO CA Limited, L=Salford, S=Greater Manchester, C=GB            1/19/2038 12:59:59 AM
```

---

## 4. Testing one node, or a name that does not resolve yet

`-HostName` is where to connect; `-TargetHost` is the name presented to the server (SNI) and
checked against the certificate. Use both to test a single node behind a load balancer, or a
server whose DNS record is not in place yet:

```powershell
Get-CertToolboxTlsCertificate -HostName '142.251.152.119' -TargetHost 'www.google.com' |
    Format-List HostName, TargetHost, ValidationPassed, PolicyError
```

```
HostName         : 142.251.152.119
TargetHost       : www.google.com
ValidationPassed : True
PolicyError      : {}
```

Without `-TargetHost`, the address itself is used as the server name, and the result changes:

```
HostName         : 142.251.152.119
TargetHost       : 142.251.152.119
ValidationPassed : False
PolicyError      : {RemoteCertificateNameMismatch, RemoteCertificateChainErrors}
```

---

## 5. Checking revocation

Revocation is not checked by default (`RevocationMode` is `NoCheck`). Add `-CheckRevocation`:

```powershell
Get-CertToolboxTlsCertificate 'revoked.badssl.com' -CheckRevocation |
    Format-List RevocationMode, ValidationPassed, PolicyError, ChainStatus
```

```
RevocationMode   : Online
ValidationPassed : False
PolicyError      : {RemoteCertificateChainErrors}
ChainStatus      : {Revoked}
```

This makes the machine contact the CA's revocation service, so the call is slower and needs
outbound access to it.

---

## 6. Saving the certificates to files

```powershell
$r = Get-CertToolboxTlsCertificate 'www.google.com'
$i = 0
foreach ($c in $r.ServerChain) {
    $bytes = $c.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    [System.IO.File]::WriteAllBytes("$PWD\google-$i.cer", $bytes)
    $i++
}
```

```
Name         Length
----         ------
google-0.cer    888
google-1.cer    674
google-2.cer    894
```

For PEM text instead:

```powershell
"-----BEGIN CERTIFICATE-----`n" +
    [System.Convert]::ToBase64String($r.Certificate.Certificate.RawData, 'InsertLineBreaks') +
    "`n-----END CERTIFICATE-----"
```

---

## 7. Finding which TLS versions an endpoint accepts

```powershell
Test-CertToolboxTlsProtocol -HostName 'www.google.com' |
    Format-Table Protocol, Negotiated, NegotiatedProtocol, CipherSuite, ErrorMessage
```

```
Protocol Negotiated NegotiatedProtocol CipherSuite                             ErrorMessage
-------- ---------- ------------------ -----------                             ------------
Ssl3          False                                                            The client and server cannot communicate, because they do not possess a common algorithm.
Tls            True Tls                TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
Tls11          True Tls11              TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
Tls12          True Tls12              TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
Tls13          True Tls13              TLS_AES_256_GCM_SHA384
```

One connection is made per version, offering only that version.

**Read `Negotiated` as "could be negotiated from this machine".** The handshake is done by your
operating system, and a version it has disabled or does not implement fails here whatever the
server accepts. In the output above, the SSL 3.0 failure comes from this Windows machine, which
cannot offer SSL 3.0 at all. A `True` is always conclusive; for a `False`, look at the error:

```powershell
Test-CertToolboxTlsProtocol -HostName 'tls-v1-2.badssl.com' -Port 1012 |
    Format-Table Protocol, Negotiated, ErrorType, ErrorMessage
```

```
Protocol Negotiated ErrorType       ErrorMessage
-------- ---------- ---------       ------------
Ssl3          False Win32Exception  The client and server cannot communicate, because they do not possess a common algorithm.
Tls           False SocketException An existing connection was forcibly closed by the remote host.
Tls11         False SocketException An existing connection was forcibly closed by the remote host.
Tls12          True
Tls13         False Win32Exception  The message received was unexpected or badly formatted.
```

Here the server closed the connection for TLS 1.0 and 1.1 and answered TLS 1.3 with something
else: those are the server's refusals. The exact messages depend on the operating system.

Use `-Protocol Tls12, Tls13` to probe only some versions.

---

## 8. Mail servers: SMTP, IMAP and POP3 with STARTTLS

Mail servers on ports 25, 587, 143 and 110 start in plaintext and upgrade to TLS on request.
`-StartTls` makes the cmdlet speak just enough of the protocol to ask for that upgrade; `-Verbose`
shows the dialogue:

```powershell
Get-CertToolboxTlsCertificate -HostName 'smtp.gmail.com' -Port 587 -StartTls Smtp -SmtpEhloName 'client.example.com' -Verbose |
    Format-List HostName, Port, StartTls, Protocol, ValidationPassed
```

```
VERBOSE: Smtp S: 220 smtp.gmail.com ESMTP 5b1f17b1804b1-4a18bbaf68esm25973935e9.4 - gsmtp
VERBOSE: Smtp C: EHLO client.example.com
VERBOSE: Smtp S: 250-smtp.gmail.com at your service, [87.121.209.8]
VERBOSE: Smtp S: 250-SIZE 35882577
VERBOSE: Smtp S: 250-8BITMIME
VERBOSE: Smtp S: 250-STARTTLS
VERBOSE: Smtp S: 250-ENHANCEDSTATUSCODES
VERBOSE: Smtp S: 250-PIPELINING
VERBOSE: Smtp S: 250-CHUNKING
VERBOSE: Smtp S: 250 SMTPUTF8
VERBOSE: Smtp C: STARTTLS
VERBOSE: Smtp S: 220 2.0.0 Ready to start TLS

HostName         : smtp.gmail.com
Port             : 587
StartTls         : Smtp
Protocol         : Tls13
ValidationPassed : True
```

Everything from the earlier sections then applies unchanged: both chains, the comparison, and
`Test-CertToolboxTlsProtocol`.

- **Port.** Without `-Port`, the protocol's standard port is used: 25 for `Smtp`, 143 for `Imap`,
  110 for `Pop3`. Mail submission on 587 has to be given explicitly.

  ```powershell
  Get-CertToolboxTlsCertificate 'outlook.office365.com' -StartTls Imap   # port 143
  Test-CertToolboxTlsProtocol   'outlook.office365.com' -StartTls Pop3   # port 110
  ```

- **The server must offer the upgrade.** Its capabilities are queried first, and the command is
  only sent if `STARTTLS` (or `STLS` for POP3) is listed. Otherwise the call fails with an error
  quoting the server's reply.
- **`-SmtpEhloName`** sets the name announced to an SMTP server. It defaults to your machine's
  host name; some servers reject or delay a name they find implausible.
- **Do not use `-StartTls` on ports that expect TLS from the first byte** (465, 993, 995). The
  server waits for a TLS handshake while the cmdlet waits for a greeting, and the call ends on a
  timeout. Use those ports without `-StartTls`.

---

## 9. Finding which CAs may issue for a domain

```powershell
Get-CertToolboxCaaRecord -Name 'www.google.com' | Format-List
```

```
Name                : www.google.com
HasCaaRecord        : True
RecordSetName       : google.com
IssueRestricted     : True
Issue               : {pki.goog}
IssueWildRestricted : True
IssueWild           : {pki.goog}
Iodef               : {}
Record              : {@{Flag=0; Critical=False; Tag=issue; Value=pki.goog; CaDomain=pki.goog; Ttl=5972}}
QueriedName         : {www.google.com, google.com}
```

`www.google.com` has no CAA record of its own, so the lookup moved up to `google.com`, as a CA
does. `RecordSetName` says where the records were found and `QueriedName` lists every name tried.

How to read the result:

| Situation | What it means |
|---|---|
| `HasCaaRecord` is `False` | No CAA record anywhere up the tree: any CA may issue |
| `IssueRestricted` is `True`, `Issue` lists domains | Only those CAs may issue |
| `IssueRestricted` is `True`, `Issue` is empty | No CA may issue at all |
| `IssueWild` | The same for wildcard certificates. It repeats `Issue` unless the domain has its own `issuewild` records |

Several names at once, wildcards included (a leading `*.` is ignored for the lookup):

```powershell
Get-CertToolboxCaaRecord 'badssl.com', '*.wikipedia.org' |
    Format-Table Name, HasCaaRecord, RecordSetName, IssueRestricted, @{ n = 'Issue'; e = { $_.Issue -join ',' } }
```

```
Name            HasCaaRecord RecordSetName IssueRestricted Issue
----            ------------ ------------- --------------- -----
badssl.com             False                         False
*.wikipedia.org         True wikipedia.org            True pki.goog,letsencrypt.org
```

The raw records, including tags the cmdlet does not interpret, are in `Record`.

DNS is queried through Google's DNS-over-HTTPS service (`dns.google`), which works the same on
every platform. The names you look up are sent to that service, and the machine needs outbound
HTTPS access to it.

---

## 10. Checking many endpoints at once

All three cmdlets accept several names, from a parameter or from the pipeline. A failure on one
does not stop the others: it is written to the error stream and the next one is processed.

```powershell
$all = 'www.google.com', 'nonexistent.invalid', 'expired.badssl.com' | Get-CertToolboxTlsCertificate 2>&1
$ok     = @($all | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] })
$failed = @($all | Where-Object { $_ -is    [System.Management.Automation.ErrorRecord] })

"succeeded: $($ok.Count), failed: $($failed.Count)"
$failed | ForEach-Object { "$($_.TargetObject) -> $($_.Exception.Message)" }
```

```
succeeded: 2, failed: 1
nonexistent.invalid:443 -> No such host is known.
```

Use `2>&1` as shown to separate successes from failures. Do not count failures with
`-ErrorVariable`: it also collects errors the cmdlet handled internally and reports more than
there were.

An expiry report from the successful ones:

```powershell
$ok | Sort-Object { $_.Certificate.DaysUntilExpiry } |
    Format-Table HostName, ValidationPassed, @{ n = 'DaysUntilExpiry'; e = { $_.Certificate.DaysUntilExpiry } }, @{ n = 'NotAfter'; e = { $_.Certificate.NotAfter } }
```

```
HostName           ValidationPassed DaysUntilExpiry NotAfter
--------           ---------------- --------------- --------
expired.badssl.com            False           -4197 4/13/2015 1:59:59 AM
www.google.com                 True              63 12/11/2026 9:02:32 PM
```

Objects with `HostName`, `Port`, `TargetHost` and `StartTls` properties bind by name, so a CSV
with those columns can be piped straight in (`Import-Csv endpoints.csv | Get-CertToolboxTlsCertificate`):

```powershell
@(
    [PSCustomObject]@{ HostName = 'www.google.com' }
    [PSCustomObject]@{ HostName = 'smtp.gmail.com'; Port = 587; StartTls = 'Smtp' }
) | Get-CertToolboxTlsCertificate | Format-Table HostName, Port, StartTls, Protocol, ValidationPassed
```

```
HostName       Port StartTls Protocol ValidationPassed
--------       ---- -------- -------- ----------------
www.google.com  443          Tls13                True
smtp.gmail.com  587 Smtp     Tls13                True
```

---

## 11. Enabling logging

Logging is off until you create a config file in your user profile:

```powershell
$configDir = Join-Path $home 'Posh-CertToolbox'
New-Item -ItemType Directory -Path $configDir -Force | Out-Null
Copy-Item .\Config\Posh-CertToolbox.sample.json (Join-Path $configDir 'Posh-CertToolbox-Config.json')
```

Then edit that copy and set `Enabled` to `true`:

```json
{
  "version": "1.0",
  "Logging": {
    "Enabled": true,
    "MinimumLevel": "Information",
    "Mode": "File",
    "File": {
      "Path": "%USERPROFILE%\\Documents\\Logs",
      "FileName": "Posh-CertToolbox-{yyyyMMdd}.log"
    }
  }
}
```

The file is read on every call, so a change takes effect immediately, without re-importing the
module.

| Setting | Values |
|---|---|
| `MinimumLevel` | `Debug`, `Information` (default), `Warning`, `Error` |
| `Mode` | `File` (default) or `EventLog` |
| `File.Path` | Folder for the log file. Left out, it is a `Posh-CertToolbox` folder in the temp directory. Environment variables use the `%NAME%` form: `%USERPROFILE%\...` on Windows, `%HOME%/...` on Linux and macOS. `$HOME` is not expanded |
| `File.FileName` | A `{...}` part is a date format, so `{yyyyMMdd}` gives one file per day |
| `EventLog.*` | Log name, source and event IDs, for `Mode` `EventLog` |

What a session looks like at `Debug` level:

```
2026-10-08 22:56:23.520 [DEBUG] [Shadow] [Get-CertToolboxTlsCertificate] Cmdlet invoked (HostName=expired.badssl.com)
2026-10-08 22:56:24.148 [INFORMATION] [Shadow] [Get-CertToolboxTlsCertificate Target=expired.badssl.com:443] Handshake completed (Tls12); server sent 3 certificate(s), local chain has 3; validation failed: RemoteCertificateChainErrors, NotTimeValid.
2026-10-08 22:56:24.211 [ERROR] [Shadow] [Get-CertToolboxTlsCertificate Target=nonexistent.invalid:443] Connection or handshake failed: SocketException: No such host is known.
2026-10-08 22:56:24.256 [INFORMATION] [Shadow] [Test-CertToolboxTlsProtocol Target=www.google.com:443] Ssl3: not negotiated (Win32Exception: The client and server cannot communicate, because they do not possess a common algorithm.)
2026-10-08 22:56:24.518 [INFORMATION] [Shadow] [Get-CertToolboxCaaRecord Target=www.google.com] CAA record set found on 'google.com': issue=[pki.goog] issuewild=[pki.goog].
```

- Each cmdlet logs its call at `Debug`, each result at `Information`, and each failed host or
  name at `Error`. At `Debug` level the STARTTLS dialogue is logged too.
- A TLS version that cannot be negotiated is logged at `Information`: it is a result of the
  test, not a failure of the cmdlet.
- Logging never stops a cmdlet. If the config file is unreadable or the log cannot be written,
  you get one warning for the session and the cmdlet carries on without logging.
- `EventLog` mode needs Windows PowerShell 5.1. The first use has to run elevated, to register
  the event source. On other platforms it is skipped with one warning.

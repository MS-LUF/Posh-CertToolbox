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
12. [Testing the CRL, OCSP and issuer URLs of a chain](#12-testing-the-crl-ocsp-and-issuer-urls-of-a-chain)
13. [Finding what a server really supports](#13-finding-what-a-server-really-supports)
14. [Checking every server behind a name](#14-checking-every-server-behind-a-name)

```powershell
Import-Module .\Posh-CertToolbox.psd1
```

---

## 1. Inspecting a TLS endpoint

```powershell
Get-CertToolboxTlsCertificate -HostName 'www.google.com'
```

```
Endpoint         : www.google.com:443
RemoteAddress    : 142.251.156.119
Protocol         : Tls13
Cipher           : TLS_AES_256_GCM_SHA384
ValidationPassed : True
Subject          : CN=www.google.com
Issuer           : CN=WE2, O=Google Trust Services, C=US
NotAfter         : 2026-12-21 (68 days)
Chain            : 3 sent by the server, 4 in the local chain
```

That is a summary, not the object. Lines appear only when they have something to say
(`PolicyError`, `MissingIntermediate`, `StartTls` and others show up when relevant), and some
are computed for display: `Endpoint`, `Cipher`, `Chain`, and the `Subject`, `Issuer` and
`NotAfter` of the leaf are not property names. The object itself has many more properties;
`Format-List *` prints them all, and you can pick the ones you need:

```powershell
$r = Get-CertToolboxTlsCertificate -HostName 'www.google.com'
$r | Format-List HostName, Port, RemoteAddress, Protocol, CipherSuite, ValidationPassed, ElapsedMs
```

```
HostName         : www.google.com
Port             : 443
RemoteAddress    : 142.251.156.119
Protocol         : Tls13
CipherSuite      : TLS_AES_256_GCM_SHA384
ValidationPassed : True
ElapsedMs        : 28
```

`Format-Table` gives one line per result, which suits several endpoints:

```powershell
Get-CertToolboxTlsCertificate 'www.google.com', 'expired.badssl.com' | Format-Table
```

```
HostName           Port RemoteAddress   Protocol Valid  Days Subject
--------           ---- -------------   -------- -----  ---- -------
www.google.com     443  142.251.156.119 Tls13    True     68 CN=www.google.com
expired.badssl.com 443  104.154.89.105  Tls12    False -4202 CN=*.badssl.com, OU=PositiveSSL Wildcard, OU=Domain Control Validated
```

The other cmdlets and the lists inside their results have a short default display in the same
way. The leaf certificate is in `Certificate`:

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
certificate in their own store or download it, and others fail. One call shows both sides.

On macOS the system's TLS stack reports the chain it completed itself instead of what the
server sent, so the cmdlet reads `ServerChain` from a separate, hand-built TLS 1.2 handshake
opening to the same address, and `ServerChainSource` says `RawHello` (it is `TlsStack` on
Windows and Linux). A server that only accepts TLS 1.3 encrypts its certificates: on macOS its
`ServerChainSource` is then `Unavailable`, `ServerChain` is empty, `MissingIntermediate`,
`ServerSentRoot` and `UnusedServerCertificate` are `$null`, and a warning says why.

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
Get-CertToolboxCaaRecord -Name 'www.google.com'
```

```
Name                : www.google.com
HasCaaRecord        : True
RecordSetName       : google.com
IssueRestricted     : True
Issue               : pki.goog
IssueWildRestricted : True
IssueWild           : pki.goog
```

The whole object, with the raw records and the names tried:

```powershell
Get-CertToolboxCaaRecord -Name 'www.google.com' | Format-List *
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
Record              : {@{Flag=0; Critical=False; Tag=issue; Value=pki.goog; CaDomain=pki.goog; Ttl=21600}}
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

---

## 12. Testing the CRL, OCSP and issuer URLs of a chain

A certificate points at the services that vouch for it: the CRL where its revocation would be
published, the OCSP responder that answers for it, and the URL of its issuer's certificate (CA
Issuers). `-TestCertificateUrl` requests every one of them, for every certificate of both
chains, and puts the outcome in `UrlTest`:

```powershell
$r = Get-CertToolboxTlsCertificate 'www.microsoft.com' -TestCertificateUrl
$r.UrlTest | Format-Table @{ n = 'Subject'; e = { $_.Subject.Split(',')[0] } }, Chain, Type, Result, Signature, NextUpdate, ElapsedMs
```

```
Subject                            Chain Type      Result      Signature NextUpdate            ElapsedMs
-------                            ----- ----      ------      --------- ----------            ---------
CN=www.microsoft.com               Both  Crl       NotRevoked  Valid     10/18/2026 6:33:09 PM       127
CN=www.microsoft.com               Both  Crl       NotRevoked  Valid     10/18/2026 2:33:09 PM       119
CN=www.microsoft.com               Both  Ocsp      Good        Valid     10/17/2026 4:43:48 AM       201
CN=www.microsoft.com               Both  CaIssuers IssuerMatch                                        38
CN=www.microsoft.com               Both  CaIssuers IssuerMatch                                        20
CN=Microsoft TLS G2 RSA CA OCSP 04 Both  Crl       NotRevoked  Valid     12/31/2026 6:57:33 AM        41
CN=Microsoft TLS G2 RSA CA OCSP 04 Both  Crl       NotRevoked  Valid     12/31/2026 6:57:33 AM        43
CN=Microsoft TLS G2 RSA CA OCSP 04 Both  Ocsp      Good        Valid     10/16/2026 8:55:35 PM       175
CN=Microsoft TLS G2 RSA CA OCSP 04 Both  CaIssuers IssuerMatch                                        40
CN=Microsoft TLS G2 RSA CA OCSP 04 Both  CaIssuers IssuerMatch                                        12
CN=Microsoft TLS RSA Root G2       Both  Crl       NotRevoked  Valid     10/30/2026 5:42:07 PM        30
CN=Microsoft TLS RSA Root G2       Both  Ocsp      Good        Valid     10/16/2026 6:31:02 PM        42
CN=Microsoft TLS RSA Root G2       Both  CaIssuers IssuerMatch                                        39
```

This run also shows something a single check would hide: the leaf's two CRL URLs returned CRLs
with different `NextUpdate` times, so the two servers were not serving the same copy.

One row per certificate and URL. A certificate that lists two CRL URLs gets two rows. The root
has no such URL and no row. Each row has more than the table shows:

```powershell
$r.UrlTest | Where-Object Type -eq 'Ocsp' | Select-Object -First 1 | Format-List
```

```
Subject    : CN=www.microsoft.com, O=Microsoft Corporation, L=Redmond, S=WA, C=US
Thumbprint : ADA5F27D8ECEC5416F5FE19043310DDD305C024B
Chain      : Both
Type       : Ocsp
Url        : http://oneocsp.microsoft.com/ocsp
Result     : Good
Signature  : Valid
Reachable  : True
ThisUpdate : 10/10/2026 4:43:48 AM
NextUpdate : 10/17/2026 4:43:48 AM
Detail     : Response produced at 2026-10-10 04:43:48Z. Signed by the delegated responder certificate 'Microsoft TLS G2 RSA CA OCSP 04 External OCSP Responder 2026-09-'.
ElapsedMs  : 201
```

| `Type` | `Result` | Meaning |
|---|---|---|
| `Crl` | `NotRevoked` | The CRL was read, is current, and does not list the certificate |
| `Crl` | `Revoked` | The CRL lists the certificate |
| `Crl` | `CrlExpired` | The certificate is not listed, but the CRL is past its next update, so it proves nothing |
| `Ocsp` | `Good`, `Revoked`, `Unknown` | What the responder answered for the certificate |
| `Ocsp` | `ResponderError` | The responder refused the request; `Detail` says how |
| `CaIssuers` | `IssuerMatch` | The URL returns the issuer's certificate |
| `CaIssuers` | `IssuerMismatch` | It returns a certificate, but not the issuer's |
| `CaIssuers` | `NotACertificate` | It returns something else, an error page for instance |
| `Crl`, `Ocsp` | `InvalidSignature` | The answer is not properly signed (see below), so what it says is not reported |
| any | `Failed` | No usable answer: unreachable, HTTP error, timeout, or unreadable content. `Detail` has the error |
| any | `Skipped` | Not testable, with the reason in `Detail`: an `ldap://` URL, or an OCSP test whose issuer certificate is in neither chain |

`ThisUpdate` and `NextUpdate` are those of the CRL or of the OCSP answer, in UTC. `Reachable`
tells a server that answered with something wrong (`True`) from one that did not answer
(`False`).

**`Signature`** says whether the CRL or the OCSP answer is really from the certificate's
issuer. It is empty for CA Issuers rows.

| `Signature` | Meaning |
|---|---|
| `Valid` | A CRL: issued and signed by the certificate's issuer. An OCSP answer: about this certificate, and signed by the issuer or by a responder certificate the issuer delegated to |
| `Invalid` | The signature does not hold, the OCSP answer is about another certificate, or the responder certificate is not entitled to sign. `Result` becomes `InvalidSignature` and `Detail` says which |
| `NotVerified` | It could not be checked, and `Detail` says why: the issuer's certificate is in neither chain, the algorithm is not handled (RSASSA-PSS, Ed25519), or the CRL is issued by another CA than the certificate's issuer. `Result` keeps what the answer says |

In the OCSP row above, `Detail` shows that Microsoft's responder signs with its own
certificate, delegated by the CA, rather than with the CA's key. That certificate was checked
too: signed by the CA, marked for OCSP signing, and within its validity dates.

**`Chain`** says where the certificate comes from: `Server` (only in what the server sent),
`Local` (only in the chain this machine built) or `Both`. A certificate in both is tested once.
With a server that sends only its leaf, the intermediates appear as `Local`:

```powershell
(Get-CertToolboxTlsCertificate 'incomplete-chain.badssl.com' -TestCertificateUrl).UrlTest |
    Format-Table @{ n = 'Subject'; e = { $_.Subject.Split(',')[0] } }, Chain, Type, Result, Signature
```

```
Subject         Chain Type      Result      Signature
-------         ----- ----      ------      ---------
CN=*.badssl.com Both  Crl       NotRevoked  Valid
CN=*.badssl.com Both  CaIssuers IssuerMatch
CN=YR1          Local Crl       NotRevoked  Valid
CN=YR1          Local CaIssuers IssuerMatch
CN=Root YR      Local Crl       NotRevoked  Valid
CN=Root YR      Local CaIssuers IssuerMatch
```

The leaf's CRL signature could be verified although the server did not send the issuer: its
certificate was found in the local chain.

Those certificates carry no OCSP URL, so there is no `Ocsp` row: several public CAs no longer
run OCSP for their certificates and publish CRLs only. A missing type is not an error.

**A revoked certificate.** This is also where the difference with `ValidationPassed` shows:

```powershell
$r = Get-CertToolboxTlsCertificate 'revoked.badssl.com' -TestCertificateUrl
$r | Format-List ValidationPassed, RevocationMode
$r.UrlTest | Where-Object Result -notin 'NotRevoked', 'Good', 'IssuerMatch' |
    Format-List Subject, Chain, Type, Url, Result, Signature, NextUpdate, Detail
```

```
ValidationPassed : True
RevocationMode   : NoCheck

Subject    : CN=revoked.badssl.com
Chain      : Both
Type       : Crl
Url        : http://ye2.c.lencr.org/74.crl
Result     : Revoked
Signature  : Valid
NextUpdate : 10/19/2026 8:05:52 PM
Detail     : 1540 revoked certificate(s) listed
```

`ValidationPassed` is the operating system's verdict, and it did not check revocation because
`-CheckRevocation` was not used (section 5). The URL test read the CRL itself and found the
certificate in it. The two answer different questions and can be combined:

- `-CheckRevocation`: does this machine consider the chain revoked? A trusted answer, but it
  says little when the check cannot be made.
- `-TestCertificateUrl`: does each revocation and issuer service answer, and what does it say?
  It shows *which* URL is down, stale or wrong.

**Only the problems, across several endpoints:**

```powershell
'www.google.com', 'www.microsoft.com', 'revoked.badssl.com' |
    Get-CertToolboxTlsCertificate -TestCertificateUrl |
    ForEach-Object {
        $name = $_.HostName
        $_.UrlTest | Where-Object Result -notin 'NotRevoked', 'Good', 'IssuerMatch', 'Skipped' |
            Select-Object @{ n = 'HostName'; e = { $name } }, Type, Result, Url
    } | Format-Table
```

```
HostName           Type Result  Url
--------           ---- ------  ---
revoked.badssl.com Crl  Revoked http://ye2.c.lencr.org/74.crl
```

Things to know:

- **A valid signature is relative to the chain.** It means the answer comes from the issuer
  found in these chains; whether that issuer is trusted is the operating system's call. This
  remains a diagnosis of the infrastructure; for the trust decision, use `-CheckRevocation`.
- **Not covered:** whether a delegated OCSP responder certificate is itself revoked, and the
  scope of a partitioned or delta CRL (it is read like a full one).
- **They contact the certificate authorities' servers**, over plain HTTP because that is what
  the URLs in certificates use. An OCSP request tells the CA which certificate you asked about.
- **`UrlTest` is empty when the switch is not used.** With the switch it is a list, which can
  itself be empty when no certificate carries a URL.
- **`-TimeoutSec` applies to each request.** A URL shared by several certificates is requested
  once. A download larger than 20 MB is given up and reported as `Failed`.
- **A failing URL never fails the cmdlet.** It is a row with `Failed`.
- With logging on, each call writes one line with the number of tests and the URLs that had a
  problem.

---

## 13. Finding what a server really supports

`Test-CertToolboxTlsProtocol` (section 7) tells what *this machine* can negotiate.
`Get-CertToolboxTlsCapability` tells what *the server* supports, whatever this machine has
enabled: it sends its own handshake openings and reads the server's answers, without ever
completing a handshake.

```powershell
$c = Get-CertToolboxTlsCapability -HostName 'www.microsoft.com'
$c
$c.Protocol
```

```
Endpoint             : www.microsoft.com:443
RemoteAddress        : 23.200.213.221
Protocol             : Tls12, Tls13
CipherSuite          : 18 accepted, 0 weak
Group                : x25519, secp256r1, X25519MLKEM768
OcspStapling         : True
SecureRenegotiation  : True
ExtendedMasterSecret : True
WireChain            : 3 certificate(s)
ConnectionCount      : 39

Protocol Accepted CipherSuiteCount ServerCipherOrder Reason
-------- -------- ---------------- ----------------- ------
Ssl3     False                   0                   The server refused with the alert 'handshake_failure'.
Tls      False                   0                   The server refused with the alert 'protocol_version'.
Tls11    False                   0                   The server refused with the alert 'protocol_version'.
Tls12    True                   13 True
Tls13    True                    5 True
```

The first block is the summary shown by default: `Protocol`, `CipherSuite`, `Group` and
`WireChain` are condensed there, and hold the full lists in the object. `Reason` is the
server's own refusal: the alert it sent, or what it did instead. The result holds three lists
and a few facts.

**`CipherSuite`**: every suite the server accepts, per version, in the order it picks them.

```powershell
$c.CipherSuite | Where-Object Protocol -eq 'Tls12' |
    Format-Table Order, Name, Code, ForwardSecrecy, AuthenticatedEncryption, Weak
```

```
Order Name                                        Code   ForwardSecrecy AuthenticatedEncryption  Weak
----- ----                                        ----   -------------- -----------------------  ----
    1 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384       0xC030           True                    True False
    2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256       0xC02F           True                    True False
    3 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 0xCCA8           True                    True False
    4 TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384       0xC028           True                   False False
    5 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256       0xC027           True                   False False
    6 TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA          0xC014           True                   False False
    7 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA          0xC013           True                   False False
    8 TLS_RSA_WITH_AES_256_GCM_SHA384             0x009D          False                    True False
    9 TLS_RSA_WITH_AES_128_GCM_SHA256             0x009C          False                    True False
   10 TLS_RSA_WITH_AES_256_CBC_SHA256             0x003D          False                   False False
   11 TLS_RSA_WITH_AES_128_CBC_SHA256             0x003C          False                   False False
   12 TLS_RSA_WITH_AES_256_CBC_SHA                0x0035          False                   False False
   13 TLS_RSA_WITH_AES_128_CBC_SHA                0x002F          False                   False False
```

The three last columns are facts read from the suite's name:

| Column | True when |
|---|---|
| `ForwardSecrecy` | The key exchange is ephemeral (ECDHE or DHE), or the suite is a TLS 1.3 one |
| `AuthenticatedEncryption` | The cipher authenticates what it encrypts (GCM, CCM, ChaCha20-Poly1305), as opposed to CBC |
| `Weak` | No encryption (NULL), no server authentication (anonymous), an export-grade key, or RC4, RC2, DES, 3DES, IDEA or MD5 |

They describe the suite, not your policy: a CBC suite is not flagged `Weak`, and a suite that is
not `Weak` can still be one you do not want.

`Order` is the order the server chose them in. `ServerCipherOrder`, in the `Protocol` list, says
whether that order is the server's own preference (`True`) or just follows the order of the
offer (`False`), in which case it carries no meaning.

**`Group`**: the key-exchange groups, for TLS 1.3 and for the highest earlier version accepted.

```powershell
$c.Group
```

```
Protocol Name           Code
-------- ----           ----
Tls12    x25519           29
Tls12    secp256r1        23
Tls13    x25519           29
Tls13    secp256r1        23
Tls13    X25519MLKEM768 4588
```

`X25519MLKEM768` is a post-quantum hybrid group.

**`WireChain`**: the certificate chain exactly as the server put it on the wire, order and
duplicates included.

```powershell
$c.WireChain | Format-Table Subject, Issuer
```

```
Subject                                                              Issuer
-------                                                              ------
CN=www.microsoft.com, O=Microsoft Corporation, L=Redmond, S=WA, C=US CN=Microsoft TLS G2 RSA CA OCSP 04, O=Microsoft Corporation, C=US
CN=Microsoft TLS G2 RSA CA OCSP 04, O=Microsoft Corporation, C=US    CN=Microsoft TLS RSA Root G2, O=Microsoft Corporation, C=US
CN=Microsoft TLS RSA Root G2, O=Microsoft Corporation, C=US          CN=DigiCert Global Root G2, OU=www.digicert.com, O=DigiCert Inc, C=US
```

**Facts**: `OcspStapling` (the server sends an OCSP answer with its certificate),
`SecureRenegotiation` and `ExtendedMasterSecret`.

**Finding weak suites across servers:**

```powershell
Get-CertToolboxTlsCapability 'rc4.badssl.com', 'www.google.com' | ForEach-Object {
    $name = $_.HostName
    $_.CipherSuite | Where-Object Weak | Select-Object @{ n = 'HostName'; e = { $name } }, Protocol, Name
} | Format-Table
```

```
HostName       Protocol Name
--------       -------- ----
rc4.badssl.com Tls      TLS_ECDHE_RSA_WITH_RC4_128_SHA
rc4.badssl.com Tls      TLS_RSA_WITH_RC4_128_SHA
rc4.badssl.com Tls11    TLS_ECDHE_RSA_WITH_RC4_128_SHA
rc4.badssl.com Tls11    TLS_RSA_WITH_RC4_128_SHA
rc4.badssl.com Tls12    TLS_ECDHE_RSA_WITH_RC4_128_SHA
rc4.badssl.com Tls12    TLS_RSA_WITH_RC4_128_SHA
www.google.com Tls      TLS_RSA_WITH_3DES_EDE_CBC_SHA
www.google.com Tls11    TLS_RSA_WITH_3DES_EDE_CBC_SHA
www.google.com Tls12    TLS_RSA_WITH_3DES_EDE_CBC_SHA
```

**Server or client? Compare the two cmdlets.** Here both say SSL 3.0 does not work, but for
different reasons:

```powershell
(Get-CertToolboxTlsCapability 'www.google.com' -Protocol Ssl3, Tls, Tls12).Protocol | Format-Table Protocol, Accepted, Reason
Test-CertToolboxTlsProtocol 'www.google.com' -Protocol Ssl3, Tls, Tls12 | Format-Table Protocol, Negotiated, ErrorMessage
```

```
Protocol Accepted Reason
-------- -------- ------
Ssl3        False The server refused with the alert 'protocol_version'.
Tls          True
Tls12        True

Protocol Negotiated ErrorMessage
-------- ---------- ------------
Ssl3          False The client and server cannot communicate, because they do not possess a common algorithm.
Tls            True
Tls12          True
```

The first table is the server's answer: it refuses SSL 3.0. The second is this Windows
machine's: it could not even offer it. When the first says `True` and the second `False`, the
server supports the version and the problem is on the client.

**Mail servers** work the same way with `-StartTls`; the plaintext exchange is repeated on every
connection:

```powershell
$m = Get-CertToolboxTlsCapability -HostName 'smtp.gmail.com' -Port 587 -StartTls Smtp -Protocol Tls12, Tls13
$m.Protocol | Format-Table Protocol, Accepted, CipherSuiteCount, ServerCipherOrder
```

```
Protocol Accepted CipherSuiteCount ServerCipherOrder
-------- -------- ---------------- -----------------
Tls12        True               14             False
Tls13        True                3             False
```

That scan took 35 connections and 2.4 seconds.

Things to know:

- **It makes many connections.** One per accepted cipher suite and per group tried: 39 for the
  first example. The server sees each as an abandoned handshake, and an intrusion detection
  system may notice. `-Protocol` narrows the scan.
- **TLS 1.3 hides the rest of the handshake.** For a server that only accepts TLS 1.3,
  `OcspStapling`, `SecureRenegotiation`, `ExtendedMasterSecret` and `WireChain` are empty. Use
  `Get-CertToolboxTlsCertificate` for the chain.
- **Nothing is validated.** The handshake is never completed, so no certificate is checked and
  no key is exchanged; `WireChain` is what was sent, not what is trusted.
- **Every suite of the IANA registry is offered**, about 350, which is how NULL, EXPORT,
  anonymous and RC4 suites are found. A suite outside the registry would show as its code.
- **Groups before TLS 1.3 are elliptic curves only.** The finite-field parameters of DHE suites
  are not reported. SSL 2.0 is not probed.
- **A port that does not speak TLS** gives a result whose versions are all refused, with the
  reason. Only an endpoint that cannot be reached at all is an error.

---

## 14. Checking every server behind a name

A name often resolves to several addresses, each a different node or data centre. By default
the cmdlets connect to the first one that answers, so a node with an old certificate or a
different configuration goes unseen. `-EveryAddress` probes each address in turn and returns
one result per address; `RemoteAddress` tells them apart.

```powershell
$r = Get-CertToolboxTlsCertificate 'outlook.office365.com' -EveryAddress
$r | Format-Table RemoteAddress, Protocol, ValidationPassed, @{ n = 'Thumbprint'; e = { $_.Certificate.Thumbprint } }, ElapsedMs
```

```
RemoteAddress         Protocol ValidationPassed Thumbprint                               ElapsedMs
-------------         -------- ---------------- ----------                               ---------
52.97.233.114         Tls13                True C7C19E04464D744D810EF31A24C54FC22A7909C5       124
52.98.227.146         Tls13                True C7C19E04464D744D810EF31A24C54FC22A7909C5        36
52.98.178.146         Tls13                True C7C19E04464D744D810EF31A24C54FC22A7909C5        25
40.99.155.50          Tls13                True C7C19E04464D744D810EF31A24C54FC22A7909C5        24
52.97.201.2           Tls13                True C7C19E04464D744D810EF31A24C54FC22A7909C5        25
40.99.153.130         Tls13                True C7C19E04464D744D810EF31A24C54FC22A7909C5        24
40.99.214.50          Tls13                True C7C19E04464D744D810EF31A24C54FC22A7909C5        26
40.99.220.130         Tls13                True C7C19E04464D744D810EF31A24C54FC22A7909C5        25
2603:1026:c0a:8b5::2  Tls13                True C7C19E04464D744D810EF31A24C54FC22A7909C5        26
2603:1026:c0a:185f::2 Tls13                True C7C19E04464D744D810EF31A24C54FC22A7909C5        25
2603:1026:c0a:1857::2 Tls13                True C7C19E04464D744D810EF31A24C54FC22A7909C5        25
2603:1026:c0a:8e8::2  Tls13                True C7C19E04464D744D810EF31A24C54FC22A7909C5        24
2603:1026:c0a:185a::2 Tls13                True C7C19E04464D744D810EF31A24C54FC22A7909C5        25
2603:1026:c0a:1860::2 Tls13                True C7C19E04464D744D810EF31A24C54FC22A7909C5        25
2603:1026:c0a:851::2  Tls13                True C7C19E04464D744D810EF31A24C54FC22A7909C5        28
2603:1026:c0a:1883::2 Tls13                True C7C19E04464D744D810EF31A24C54FC22A7909C5        26
```

The name you gave is still what is presented to each server and checked against its
certificate; only the address connected to changes.

**Do they all serve the same certificate?** Group by thumbprint: one group means yes.

```powershell
$r | Group-Object { $_.Certificate.Thumbprint } | Format-Table Count, Name
```

```
Count Name
----- ----
   16 C7C19E04464D744D810EF31A24C54FC22A7909C5
```

Two groups would mean some nodes serve another certificate; the `RemoteAddress` of the
smaller group says which. The same works on anything else in the result: `Protocol`,
`ValidationPassed`, the number of certificates in `ServerChain`.

**One family only.** `-AddressFamily IPv4` or `IPv6` limits the addresses probed:

```powershell
Get-CertToolboxTlsCertificate 'www.cloudflare.com' -EveryAddress -AddressFamily IPv4 |
    Format-Table HostName, RemoteAddress, Protocol, ValidationPassed
```

```
HostName           RemoteAddress Protocol ValidationPassed
--------           ------------- -------- ----------------
www.cloudflare.com 104.16.123.96 Tls13                True
www.cloudflare.com 104.16.124.96 Tls13                True
```

Without `-EveryAddress`, `-AddressFamily` chooses which family the single connection uses,
which is a quick way to test a service over IPv6:

```powershell
Get-CertToolboxTlsCertificate 'www.google.com' -AddressFamily IPv6 | Format-List HostName, RemoteAddress, Protocol
```

```
HostName      : www.google.com
RemoteAddress : 2001:4860:4827:7700::
Protocol      : Tls13
```

**The other TLS cmdlets take the same two parameters.** `Test-CertToolboxTlsProtocol` returns
its rows once per address:

```powershell
Test-CertToolboxTlsProtocol 'www.cloudflare.com' -EveryAddress -Protocol Tls11, Tls13 |
    Format-Table RemoteAddress, Protocol, Negotiated
```

```
RemoteAddress        Protocol Negotiated
-------------        -------- ----------
104.16.123.96        Tls11         False
104.16.123.96        Tls13          True
104.16.124.96        Tls11         False
104.16.124.96        Tls13          True
2606:4700::6810:7c60 Tls11         False
2606:4700::6810:7c60 Tls13          True
2606:4700::6810:7b60 Tls11         False
2606:4700::6810:7b60 Tls13          True
```

`Get-CertToolboxTlsCapability` repeats its whole scan for each address, so narrow it:

```powershell
Get-CertToolboxTlsCapability 'www.cloudflare.com' -EveryAddress -AddressFamily IPv4 -Protocol Tls12, Tls13 |
    Format-Table RemoteAddress, @{ n = 'Versions'; e = { ($_.Protocol | Where-Object Accepted).Protocol -join ',' } },
        @{ n = 'Suites'; e = { @($_.CipherSuite).Count } }, ConnectionCount
```

```
RemoteAddress Versions    Suites ConnectionCount
------------- --------    ------ ---------------
104.16.123.96 Tls12,Tls13     23              43
104.16.124.96 Tls12,Tls13     23              43
```

Things to know:

- **"Every address" means every address your resolver returns.** Large services answer
  differently depending on where and whom you ask, and rotate their answers: the first table
  above lists 16 addresses, and another run a moment earlier listed others. It is not a list
  of every node that exists.
- **An address that cannot be reached is an error for that address only**; the others are
  still returned. A machine without IPv6 connectivity gets one error per IPv6 address, which
  `-AddressFamily IPv4` avoids.
- **A name with no address of the family asked for is an error:**

  ```powershell
  Get-CertToolboxTlsCertificate 'badssl.com' -EveryAddress -AddressFamily IPv6
  ```

  ```
  'badssl.com' has no IPv6 address.
  ```

- **To test one address you already know**, use `-HostName` with the address and `-TargetHost`
  with the name (section 4).

---
external help file: Posh-CertToolbox-help.xml
Module Name: Posh-CertToolbox
online version:
schema: 2.0.0
---

# Get-CertToolboxTlsCertificate

## SYNOPSIS
Connects to a TLS endpoint and reports the negotiated session, the certificate chain the
server sent, and the chain this machine builds from it.

## SYNTAX

```
Get-CertToolboxTlsCertificate [-HostName] <String[]> [-Port <Int32>] [-TargetHost <String>]
 [-Protocol <String[]>] [-TimeoutSec <Int32>] [-CheckRevocation] [-StartTls <String>] [-SmtpEhloName <String>]
 [-TestCertificateUrl] [-EveryAddress] [-AddressFamily <String>] [<CommonParameters>]
```

## DESCRIPTION
One connection gives both views of the chain, and three properties comparing them.

ServerChain holds the certificates the server actually sent, leaf first.
This is what
every client receives, whatever its own stores contain.

LocalChain holds the chain this machine built to a root, using the server's
certificates, its own certificate stores and, where the platform does it, downloaded
intermediates.
Each element carries its own Status flags (empty when it has no error).

MissingIntermediate lists the certificates the local chain needed that the server did
not send (roots excluded).
Clients that cannot find them on their own will fail.

ServerSentRoot is true when the server sent a self-signed certificate after the leaf,
which is useless.

UnusedServerCertificate lists the certificates the server sent that this machine did
not use.

The connection is never refused because of the certificate: validation problems are
reported in ValidationPassed, PolicyError and ChainStatus instead, so that broken
endpoints can be inspected.

The handshake is done by the operating system's TLS stack.
The protocol versions and
cipher suites that can be offered therefore depend on the machine this runs on, and
CipherSuite is only available under PowerShell 7 and later.

Mail servers that start in plaintext and upgrade to TLS are reached with the StartTls
parameter: the cmdlet speaks just enough SMTP, IMAP or POP3 to check that the server
offers the upgrade and to request it, then does the same handshake.
Use the Verbose
switch to see that dialogue.

With the TestCertificateUrl switch, every CRL, OCSP and issuer-certificate (CA Issuers)
URL found in the certificates of both chains is requested, and the UrlTest property
lists one result per certificate and URL: whether it answered, the dates it gave, and
a Result.
For a CRL the Result is NotRevoked, Revoked or CrlExpired; for OCSP it is
Good, Revoked, Unknown or ResponderError; for CA Issuers it is IssuerMatch,
IssuerMismatch or NotACertificate; and for any of them Failed (no usable answer) or
Skipped (not testable, with the reason in Detail).

The signature of each CRL and OCSP answer is verified against the certificate's issuer
and shown in the Signature column: Valid, Invalid, or NotVerified when it could not be
checked (the reason is in Detail).
An OCSP answer must also be about the certificate
asked for, and may be signed by a responder certificate the issuer delegated to.
When
the signature is Invalid, the Result becomes InvalidSignature, because such an answer
proves nothing.

These tests show whether the revocation and issuer infrastructure answers and what it
says.
A valid signature means the answer comes from the issuer found in these chains;
whether that issuer is itself trusted is not decided here, so this remains a diagnosis
and CheckRevocation gives the operating system's own verdict.
The tests contact the
certificate authorities' servers, over plain HTTP as those URLs require.

The default display is a summary of about ten lines, and some of them are computed
for display and are not property names: Endpoint, Cipher, Chain, and the Subject,
Issuer and NotAfter of the leaf, which are read from the Certificate property.
Pipe
the result to Format-List with an asterisk to see every property, or to Format-Table
for one line per result.
The certificates of a chain are shown as a table.

## EXAMPLES

### EXAMPLE 1
```
Get-CertToolboxTlsCertificate -HostName 'www.example.com'
```

### EXAMPLE 2
```
(Get-CertToolboxTlsCertificate 'www.example.com').ServerChain | Select-Object Subject, Issuer, NotAfter
```

Lists the certificates the server sends.

### EXAMPLE 3
```
Get-CertToolboxTlsCertificate -HostName '192.0.2.10' -TargetHost 'www.example.com' -Port 8443
```

Connects to a specific address while presenting www.example.com as the server name.

### EXAMPLE 4
```
Get-CertToolboxTlsCertificate -HostName 'mail.example.com' -Port 587 -StartTls Smtp -Verbose
```

Inspects the certificate of a mail submission server, showing the SMTP dialogue.

### EXAMPLE 5
```
(Get-CertToolboxTlsCertificate 'www.example.com' -TestCertificateUrl).UrlTest | Format-Table Subject, Chain, Type, Result, Signature, NextUpdate, Url
```

Tests the CRL, OCSP and CA Issuers URLs of every certificate of both chains.

### EXAMPLE 6
```
Get-CertToolboxTlsCertificate 'www.example.com' -EveryAddress | Group-Object { $_.Certificate.Thumbprint } | Select-Object Count, Name
```

Probes every address behind the name and shows whether they all serve the same certificate.

## PARAMETERS

### -HostName
One or more DNS names or IP addresses to connect to.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: ComputerName, DnsName

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Port
TCP port.
Defaults to 443, or with StartTls to the protocol's standard port: 25 for
Smtp, 143 for Imap, 110 for Pop3.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 443
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -TargetHost
Name sent as SNI and matched against the certificate, when it differs from HostName (for
example when connecting to an IP address or to one node behind a load balancer).

```yaml
Type: String
Parameter Sets: (All)
Aliases: ServerName, SNI

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Protocol
Protocol versions to offer.
SystemDefault (the default) lets the operating system
choose.
Use Test-CertToolboxTlsProtocol to probe each version separately.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: @('SystemDefault')
Accept pipeline input: False
Accept wildcard characters: False
```

### -TimeoutSec
Timeout, in seconds, for the TCP connection and for each step of the handshake.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 10
Accept pipeline input: False
Accept wildcard characters: False
```

### -CheckRevocation
Also checks certificate revocation while building the local chain.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -StartTls
The mail protocol to speak in plaintext before upgrading to TLS: Smtp, Imap or Pop3.
Omit it for a server that expects TLS from the first byte (HTTPS, SMTPS on 465, IMAPS on
993, POP3S on 995).

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -SmtpEhloName
The name announced in the SMTP EHLO command, with StartTls Smtp.
Defaults to this
machine's host name; set it when a server rejects or delays that name.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TestCertificateUrl
Also requests every CRL, OCSP and CA Issuers URL found in the certificates of both
chains, and reports the outcome in the UrlTest property.
TimeoutSec applies to each
request.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -EveryAddress
Probes every IP address the name resolves to, instead of the first one that answers,
and returns one result per address; RemoteAddress tells them apart.
Use it to find a
node behind a load-balanced name that serves a different certificate or chain.
An
address that cannot be reached is an error for that address only.
The addresses are
the ones this machine's resolver returns.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -AddressFamily
Uses only the IPv4 or only the IPv6 addresses of the name.
With EveryAddress it limits
the addresses probed; without it, it chooses which family to connect over.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.String. Host names as strings, or objects with HostName, Port, TargetHost and StartTls properties.
## OUTPUTS

### PSCustomObject (type name CertToolbox.TlsCertificate), one per host.
## NOTES

## RELATED LINKS

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
 [<CommonParameters>]
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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.String. Host names as strings, or objects with HostName, Port, TargetHost and StartTls properties.
## OUTPUTS

### PSCustomObject (type name CertToolbox.TlsCertificate), one per host.
## NOTES

## RELATED LINKS

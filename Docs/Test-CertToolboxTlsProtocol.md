---
external help file: Posh-CertToolbox-help.xml
Module Name: Posh-CertToolbox
online version:
schema: 2.0.0
---

# Test-CertToolboxTlsProtocol

## SYNOPSIS
Probes a TLS endpoint once per protocol version and reports which ones could be
negotiated.

## SYNTAX

```
Test-CertToolboxTlsProtocol [-HostName] <String[]> [-Port <Int32>] [-TargetHost <String>]
 [-Protocol <String[]>] [-TimeoutSec <Int32>] [-StartTls <String>] [-SmtpEhloName <String>]
 [<CommonParameters>]
```

## DESCRIPTION
Makes a separate connection for each protocol version, offering only that version, and
returns one result per version.

Read the Negotiated property as "could be negotiated from this machine", not as "the
server supports it".
The handshake is done by the operating system's TLS stack, and a
version that the local system has disabled or does not implement fails here whatever the
server accepts; ErrorType and ErrorMessage carry the underlying failure so the two cases
can be told apart.
A $true result is always conclusive; a $false one only is when the
same version works from this machine against another server.

Mail servers that start in plaintext and upgrade to TLS are probed with the StartTls
parameter; the plaintext exchange is then repeated on each connection.
When that
exchange itself fails (the server does not offer the upgrade, for instance), every
version is reported as not negotiated with that error.

## EXAMPLES

### EXAMPLE 1
```
Test-CertToolboxTlsProtocol -HostName 'www.example.com' | Format-Table Protocol, Negotiated, CipherSuite, ErrorMessage
```

### EXAMPLE 2
```
Test-CertToolboxTlsProtocol -HostName 'mail.example.com' -Port 993 -Protocol Tls12, Tls13
```

### EXAMPLE 3
```
Test-CertToolboxTlsProtocol -HostName 'mail.example.com' -StartTls Smtp
```

Probes the TLS versions of a mail server on port 25, upgrading with STARTTLS each time.

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
Name sent as SNI, when it differs from HostName.

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
The protocol versions to probe.
Defaults to all of Ssl3, Tls, Tls11, Tls12 and Tls13.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: @('Ssl3', 'Tls', 'Tls11', 'Tls12', 'Tls13')
Accept pipeline input: False
Accept wildcard characters: False
```

### -TimeoutSec
Timeout, in seconds, for each connection and each step of its handshake.

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

### -StartTls
The mail protocol to speak in plaintext before upgrading to TLS: Smtp, Imap or Pop3.
Omit it for a server that expects TLS from the first byte.

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
machine's host name.

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

### PSCustomObject (type name CertToolbox.TlsProtocolResult), one per host and protocol.
## NOTES

## RELATED LINKS

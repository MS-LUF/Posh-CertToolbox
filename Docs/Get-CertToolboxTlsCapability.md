---
external help file: Posh-CertToolbox-help.xml
Module Name: Posh-CertToolbox
online version:
schema: 2.0.0
---

# Get-CertToolboxTlsCapability

## SYNOPSIS
Finds what a TLS server supports: protocol versions, cipher suites, key-exchange groups
and a few handshake features.

## SYNTAX

```
Get-CertToolboxTlsCapability [-HostName] <String[]> [-Port <Int32>] [-TargetHost <String>]
 [-Protocol <String[]>] [-TimeoutSec <Int32>] [-StartTls <String>] [-SmtpEhloName <String>] [-EveryAddress]
 [-AddressFamily <String>] [<CommonParameters>]
```

## DESCRIPTION
Sends hand-built handshake openings and reads how the server answers, without ever
completing a handshake.
What is offered therefore does not depend on what this
machine's own TLS stack has enabled, and the result is a statement about the server.
This is the difference with Test-CertToolboxTlsProtocol, which tells what this machine
can negotiate; comparing the two shows whether a failure is the server's or the
client's.

Protocol lists each version probed, whether the server accepts it, how many cipher
suites it accepts for it, and otherwise why not (the alert it sent, or what it
answered instead).

CipherSuite lists every suite accepted, per version, in the order the server picks
them, from the whole IANA registry.
ForwardSecrecy, AuthenticatedEncryption and Weak
are facts read from the suite's name; Weak marks suites with no encryption, no server
authentication, an export-grade key, or RC4, RC2, DES, 3DES, IDEA or MD5.
ServerCipherOrder, in Protocol, tells whether that order is imposed by the server or
merely follows the order of the offer.

Group lists the key-exchange groups accepted, for TLS 1.3 and for the highest earlier
version the server accepts.

OcspStapling, SecureRenegotiation, ExtendedMasterSecret and WireChain (the certificate
chain exactly as sent, duplicates and order included) are read from a handshake of TLS
1.2 or earlier.
They are empty for a server that only accepts TLS 1.3, where everything
after the first server message is encrypted.

A full scan makes one connection per accepted cipher suite and per group tried,
typically 20 to 60 per host, and the server will see each as an abandoned handshake.
Use the Protocol parameter to narrow it.
SSL 2.0 is not probed.

The default display is a summary: the accepted versions, the number of cipher suites
and how many are weak, the group names.
The Protocol, CipherSuite, Group and WireChain
properties hold the full lists, each shown as a table; pipe the result to Format-List
with an asterisk to see every property.

## EXAMPLES

### EXAMPLE 1
```
(Get-CertToolboxTlsCapability -HostName 'www.example.com').Protocol | Format-Table
```

Scans a server and shows which protocol versions it accepts.

### EXAMPLE 2
```
(Get-CertToolboxTlsCapability -HostName 'www.example.com').CipherSuite | Format-Table Protocol, Order, Name, ForwardSecrecy, Weak
```

Shows the cipher suites the server accepts, per version, in the order it picks them.

### EXAMPLE 3
```
(Get-CertToolboxTlsCapability 'www.example.com').CipherSuite | Where-Object Weak
```

Lists the weak cipher suites a server still accepts.

### EXAMPLE 4
```
Get-CertToolboxTlsCapability -HostName 'mail.example.com' -StartTls Smtp -Protocol Tls12, Tls13
```

Scans a mail server on port 25 for TLS 1.2 and 1.3 only.

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
Server name to send, when it differs from HostName.

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
Timeout, in seconds, for each connection and each read.

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
The mail protocol to speak in plaintext before TLS: Smtp, Imap or Pop3.
The exchange is
repeated on every connection.

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

### -EveryAddress
Scans every IP address the name resolves to, instead of the first one that answers,
and returns one result per address; RemoteAddress tells them apart.
The whole scan is
repeated for each address, so the number of connections is multiplied accordingly:
combine it with the Protocol parameter.

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

### PSCustomObject (type name CertToolbox.TlsCapability), one per host.
## NOTES

## RELATED LINKS

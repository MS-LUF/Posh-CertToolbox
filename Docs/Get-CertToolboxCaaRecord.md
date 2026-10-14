---
external help file: Posh-CertToolbox-help.xml
Module Name: Posh-CertToolbox
online version:
schema: 2.0.0
---

# Get-CertToolboxCaaRecord

## SYNOPSIS
Gets the DNS CAA records that apply to a domain, telling which CAs may issue for it.

## SYNTAX

```
Get-CertToolboxCaaRecord [-Name] <String[]> [-TimeoutSec <Int32>] [<CommonParameters>]
```

## DESCRIPTION
Looks up the CAA record set relevant to each name the way a CA has to (RFC 8659): the
name itself first, then each parent domain in turn until a CAA record set is found.
The
output says which name the records were found on.

HasCaaRecord is $false when no CAA record exists anywhere up the tree: issuance is not
restricted, any CA may issue.

Issue lists the CA domains allowed to issue.
IssueRestricted is $true when the record
set has at least one "issue" record; an empty Issue list with IssueRestricted $true
means no CA may issue at all.

IssueWild is the same for wildcard certificates.
When the record set has no "issuewild"
record, wildcard issuance follows the "issue" records, and IssueWild repeats them.

Record holds every record of the set as returned, including tags this cmdlet does not
interpret.

DNS is queried through Google's DNS-over-HTTPS API (dns.google), so it works identically
on every platform; the names queried are sent to that service.

The default display leaves out the Record and QueriedName properties; pipe the result
to Format-List with an asterisk to see every property.

## EXAMPLES

### EXAMPLE 1
```
Get-CertToolboxCaaRecord -Name 'www.example.com'
```

Shows which CAs may issue for www.example.com and where the restriction is defined.

### EXAMPLE 2
```
'example.com', 'example.org' | Get-CertToolboxCaaRecord | Select-Object Name, RecordSetName, Issue, IssueWild
```

## PARAMETERS

### -Name
One or more DNS names.
A leading "*." is ignored, so a wildcard name can be given as is.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: Domain, DnsName, HostName

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -TimeoutSec
Timeout, in seconds, of each DNS query.

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.String. Names can be piped in, as strings or as objects with a Name property.
## OUTPUTS

### PSCustomObject (type name CertToolbox.CaaRecord), one per name.
## NOTES

## RELATED LINKS

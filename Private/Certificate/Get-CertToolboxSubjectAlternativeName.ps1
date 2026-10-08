function Get-CertToolboxSubjectAlternativeName {
    <#
    .SYNOPSIS
        Returns the DNS names and IP addresses of a certificate's Subject Alternative Name
        extension.
    .DESCRIPTION
        Decodes the extension's DER bytes directly instead of parsing the text the runtime
        produces for it: that text differs by platform ("DNS Name=" on Windows, "DNS:" with
        OpenSSL) and is localized on Windows, so it cannot be parsed reliably in a module meant
        to run everywhere.

        The extension value is a SEQUENCE of GeneralName (RFC 5280, section 4.2.1.6). Only
        dNSName (context tag 2) and iPAddress (context tag 7) entries are returned; other name
        forms are skipped.
    .PARAMETER Certificate
        The certificate to read.
    .OUTPUTS
        System.String, one per name. Nothing when the certificate has no such extension.
    .EXAMPLE
        Get-CertToolboxSubjectAlternativeName -Certificate $certificate
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
    )

    $extension = $Certificate.Extensions['2.5.29.17']
    if (-not $extension) {
        return
    }

    $bytes = $extension.RawData
    $sequence = Read-CertToolboxDerHeader -Bytes $bytes -Offset 0
    if (-not $sequence -or $sequence.Tag -ne 0x30) {
        Write-Verbose "Subject Alternative Name extension of '$($Certificate.Subject)' is not a DER SEQUENCE; ignored."
        return
    }

    $end = [Math]::Min($bytes.Length, $sequence.ValueOffset + $sequence.Length)
    $offset = $sequence.ValueOffset

    while ($offset -lt $end) {
        $item = Read-CertToolboxDerHeader -Bytes $bytes -Offset $offset
        if (-not $item -or $item.ValueOffset + $item.Length -gt $bytes.Length) {
            break
        }

        if ($item.Tag -eq 0x82) {
            [System.Text.Encoding]::ASCII.GetString($bytes, $item.ValueOffset, $item.Length)
        } elseif ($item.Tag -eq 0x87 -and ($item.Length -eq 4 -or $item.Length -eq 16)) {
            $addressBytes = New-Object byte[] $item.Length
            [System.Array]::Copy($bytes, $item.ValueOffset, $addressBytes, 0, $item.Length)
            ([System.Net.IPAddress]::new($addressBytes)).ToString()
        }

        $offset = $item.ValueOffset + $item.Length
    }
}

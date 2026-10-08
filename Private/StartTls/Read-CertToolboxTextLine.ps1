function Read-CertToolboxTextLine {
    <#
    .SYNOPSIS
        Reads one CRLF-terminated line of a plaintext protocol from a stream.
    .DESCRIPTION
        Reads one byte at a time, on purpose: a buffered reader could read past the end of the
        line, and after a STARTTLS exchange the very next bytes on the stream belong to the TLS
        handshake, which SslStream must receive intact. Confirmed by direct test against public
        SMTP, IMAP and POP3 servers under Windows PowerShell 5.1 and PowerShell 7.

        The read is bounded by the stream's own timeout (the socket's ReceiveTimeout, set by
        Connect-CertToolboxTcpClient) and by MaxLength, so a server that never ends its line
        cannot hold the call or exhaust memory.
    .PARAMETER Stream
        The connected stream to read from.
    .PARAMETER MaxLength
        Maximum accepted line length, in characters.
    .OUTPUTS
        System.String, without its line terminator.
    .EXAMPLE
        Read-CertToolboxTextLine -Stream $client.GetStream()
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.IO.Stream] $Stream,

        [Parameter()]
        [int] $MaxLength = 4096
    )

    $builder = [System.Text.StringBuilder]::new()
    while ($true) {
        $value = $Stream.ReadByte()
        if ($value -lt 0) {
            throw [System.IO.EndOfStreamException]::new('The server closed the connection before completing its reply.')
        }
        if ($value -eq 10) {
            break
        }
        if ($value -ne 13) {
            $null = $builder.Append([char]$value)
            if ($builder.Length -gt $MaxLength) {
                throw [System.Net.ProtocolViolationException]::new("The server sent a line longer than $MaxLength characters.")
            }
        }
    }

    $builder.ToString()
}

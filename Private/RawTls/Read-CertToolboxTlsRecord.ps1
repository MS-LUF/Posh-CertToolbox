function Read-CertToolboxTlsRecord {
    <#
    .SYNOPSIS
        Reads one TLS record from a stream.
    .DESCRIPTION
        A record is a five-byte header (content type, version, length) followed by that many
        bytes. Both parts are read in full, whatever number of reads the network needs.

        Throws when the peer closes the connection, and when the header is not that of a TLS
        record: a plain-text service answering on the port (an HTTP error page, an SMTP
        greeting) would otherwise be read as a record of absurd length.
    .PARAMETER Stream
        The connected stream to read from.
    .OUTPUTS
        PSCustomObject with Type (20 change cipher spec, 21 alert, 22 handshake, 23 application
        data) and Payload (bytes).
    .EXAMPLE
        Read-CertToolboxTlsRecord -Stream $client.GetStream()
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [System.IO.Stream] $Stream
    )

    $header = New-Object byte[] 5
    $read = 0
    while ($read -lt 5) {
        $count = $Stream.Read($header, $read, 5 - $read)
        if ($count -le 0) {
            throw [System.IO.EndOfStreamException]::new('The server closed the connection.')
        }
        $read += $count
    }

    # Bytes are widened before shifting: a byte shifted left stays a byte and loses the value.
    $length = ([int]$header[3] -shl 8) -bor [int]$header[4]
    if ($header[0] -lt 20 -or $header[0] -gt 23 -or $header[1] -ne 3 -or $length -gt 18432) {
        throw [System.Net.ProtocolViolationException]::new('The server did not answer with a TLS record.')
    }

    $payload = New-Object byte[] $length
    $read = 0
    while ($read -lt $length) {
        $count = $Stream.Read($payload, $read, $length - $read)
        if ($count -le 0) {
            throw [System.IO.EndOfStreamException]::new('The server closed the connection in the middle of a record.')
        }
        $read += $count
    }

    [PSCustomObject]@{
        Type    = [int]$header[0]
        Payload = $payload
    }
}

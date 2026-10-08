function Send-CertToolboxTextLine {
    <#
    .SYNOPSIS
        Writes one CRLF-terminated ASCII line of a plaintext protocol to a stream.
    .PARAMETER Stream
        The connected stream to write to.
    .PARAMETER Line
        The command to send, without its line terminator.
    .EXAMPLE
        Send-CertToolboxTextLine -Stream $stream -Line 'STARTTLS'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.IO.Stream] $Stream,

        [Parameter(Mandatory)]
        [string] $Line
    )

    $bytes = [System.Text.Encoding]::ASCII.GetBytes("$Line`r`n")
    $Stream.Write($bytes, 0, $bytes.Length)
    $Stream.Flush()
}

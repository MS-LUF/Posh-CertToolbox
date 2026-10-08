function Invoke-CertToolboxStartTls {
    <#
    .SYNOPSIS
        Runs the plaintext exchange that upgrades a connection to TLS, for the given protocol.
    .DESCRIPTION
        Dispatches to the protocol's own function. Adding a protocol means adding one such
        function, one case here, one default port in the module file and one allowed value on
        the public StartTls parameters.

        Each line of the dialogue is also written to the verbose stream as it happens, so it is
        visible even when the exchange fails part way.
    .PARAMETER StartTls
        The application protocol spoken before TLS: Smtp, Imap or Pop3.
    .PARAMETER Stream
        The connected stream to the server.
    .PARAMETER SmtpEhloName
        The name to announce in the SMTP EHLO command. Ignored for other protocols.
    .OUTPUTS
        System.String. The dialogue, one line per string, prefixed "C: " (client) or "S: "
        (server).
    .EXAMPLE
        Invoke-CertToolboxStartTls -StartTls Smtp -Stream $client.GetStream()
    #>
    [CmdletBinding()]
    [OutputType([string])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'StartTls is the name of the mechanism, not a plural - PSUseSingularNouns false-positives on the trailing "s" of TLS.')]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Smtp', 'Imap', 'Pop3')]
        [string] $StartTls,

        [Parameter(Mandatory)]
        [System.IO.Stream] $Stream,

        [Parameter()]
        [string] $SmtpEhloName
    )

    $handler = @{
        Smtp = 'Invoke-CertToolboxSmtpStartTls'
        Imap = 'Invoke-CertToolboxImapStartTls'
        Pop3 = 'Invoke-CertToolboxPop3StartTls'
    }[$StartTls]

    $handlerParameter = @{ Stream = $Stream }
    if ($StartTls -eq 'Smtp' -and $SmtpEhloName) {
        $handlerParameter.EhloName = $SmtpEhloName
    }

    # Piped, not collected first: each line reaches the verbose stream as the protocol function
    # emits it, before a later step of the exchange can throw.
    & $handler @handlerParameter | ForEach-Object {
        Write-Verbose "$StartTls $_"
        $_
    }
}

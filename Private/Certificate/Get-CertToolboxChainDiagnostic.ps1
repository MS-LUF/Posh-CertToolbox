function Get-CertToolboxChainDiagnostic {
    <#
    .SYNOPSIS
        Compares the certificates a server sent with the chain the local machine built.
    .DESCRIPTION
        Derives the three findings that explain most "works here, fails there" chain problems:

        - MissingIntermediate: certificates the local chain needed, other than a self-signed
          root, that the server did not send. The local machine found them in its own stores or
          downloaded them; a client that cannot do either will fail to validate.
        - ServerSentRoot: the server sent a self-signed certificate after the leaf. It is
          harmless but useless, since a client only trusts roots from its own store.
        - UnusedServerCertificate: certificates the server sent that the local chain did not
          use, typically a cross-signed certificate bypassed in favour of a root in the local
          store.

        Certificates are matched by thumbprint.
    .PARAMETER ServerCertificate
        The certificates the server sent, leaf first.
    .PARAMETER LocalCertificate
        The certificates of the locally built chain, leaf first.
    .OUTPUTS
        PSCustomObject with MissingIntermediate, ServerSentRoot and UnusedServerCertificate.
    .EXAMPLE
        Get-CertToolboxChainDiagnostic -ServerCertificate $sent -LocalCertificate $built
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]] $ServerCertificate,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]] $LocalCertificate
    )

    $serverThumbprint = @($ServerCertificate | ForEach-Object { $_.Thumbprint })
    $localThumbprint = @($LocalCertificate | ForEach-Object { $_.Thumbprint })

    $missingIntermediate = @($LocalCertificate | Where-Object {
            $serverThumbprint -notcontains $_.Thumbprint -and -not (Test-CertToolboxSelfSigned -Certificate $_)
        })

    $serverSentRoot = $false
    $unusedServerCertificate = @()
    if ($ServerCertificate.Count -gt 1) {
        $afterLeaf = @($ServerCertificate | Select-Object -Skip 1)
        $serverSentRoot = @($afterLeaf | Where-Object { Test-CertToolboxSelfSigned -Certificate $_ }).Count -gt 0
        # Only meaningful when a local chain exists to compare against.
        if ($LocalCertificate.Count -gt 0) {
            $unusedServerCertificate = @($afterLeaf | Where-Object { $localThumbprint -notcontains $_.Thumbprint })
        }
    }

    [PSCustomObject]@{
        MissingIntermediate     = $missingIntermediate
        ServerSentRoot          = $serverSentRoot
        UnusedServerCertificate = $unusedServerCertificate
    }
}

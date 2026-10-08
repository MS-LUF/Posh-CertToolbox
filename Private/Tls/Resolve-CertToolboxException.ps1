function Resolve-CertToolboxException {
    <#
    .SYNOPSIS
        Returns the innermost exception of an exception chain.
    .DESCRIPTION
        Socket and TLS failures reach PowerShell wrapped several levels deep (a
        MethodInvocationException or AggregateException around an AuthenticationException around
        the Win32/OpenSSL error that actually says what went wrong). The innermost one carries the
        useful diagnostic, so that is what this module reports.
    .PARAMETER Exception
        The exception to unwrap.
    .OUTPUTS
        System.Exception
    .EXAMPLE
        Resolve-CertToolboxException -Exception $_.Exception
    #>
    [CmdletBinding()]
    [OutputType([System.Exception])]
    param(
        [Parameter(Mandatory)]
        [System.Exception] $Exception
    )

    $current = $Exception
    while ($current.InnerException) {
        $current = $current.InnerException
    }
    $current
}

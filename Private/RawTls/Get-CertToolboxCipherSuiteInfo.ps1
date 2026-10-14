function Get-CertToolboxCipherSuiteInfo {
    <#
    .SYNOPSIS
        Describes a cipher suite from its IANA number.
    .DESCRIPTION
        Gives the suite's registered name and three facts read from that name, which states
        the key exchange, the cipher and the hash.

        ForwardSecrecy: the key exchange is ephemeral (ECDHE or DHE), or the suite is a TLS 1.3
        one, where it always is.

        AuthenticatedEncryption: the cipher authenticates what it encrypts (GCM, CCM,
        ChaCha20-Poly1305 and the like), as opposed to CBC or stream ciphers with a separate
        MAC.

        Weak: the suite has no encryption (NULL, and the integrity-only TLS 1.3 suites), no
        authentication of the server (anonymous), a deliberately weakened key (EXPORT), or a
        broken or obsolete algorithm (RC4, RC2, DES, 3DES, IDEA, MD5).

        These are facts about the suite, not a verdict on the server: CBC suites are not
        flagged, and a suite that is not weak here can still be unwanted by a given policy.
    .PARAMETER Code
        The suite's IANA number.
    .OUTPUTS
        PSCustomObject with Name, Code (as 0xNNNN), ForwardSecrecy, AuthenticatedEncryption and
        Weak. For a number that is not in the registry, the name is the code and the three
        facts are $null.
    .EXAMPLE
        Get-CertToolboxCipherSuiteInfo -Code 0xC02F
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [int] $Code
    )

    $text = '0x{0:X4}' -f $Code
    $name = $script:CertToolboxCipherSuiteName[$Code]
    if (-not $name) {
        return [PSCustomObject]@{
            Name                    = $text
            Code                    = $text
            ForwardSecrecy          = $null
            AuthenticatedEncryption = $null
            Weak                    = $null
        }
    }

    $isTls13 = $name -notmatch '_WITH_'
    $integrityOnly = $name -cmatch '^TLS_SHA\d+_SHA\d+$'

    [PSCustomObject]@{
        Name                    = $name
        Code                    = $text
        ForwardSecrecy          = [bool]($isTls13 -or $name -cmatch '^TLS_(ECDHE|DHE)_|_DHE_')
        AuthenticatedEncryption = [bool]((-not $integrityOnly) -and $name -cmatch '_GCM|_CCM|CHACHA20_POLY1305|_MGM_|ASCONAEAD|_AEGIS_')
        Weak                    = [bool]($integrityOnly -or $name -cmatch '_NULL|_EXPORT_|_anon_|_RC4_|_RC2_|_DES_|_DES40_|_3DES_|_IDEA_|_MD5$')
    }
}

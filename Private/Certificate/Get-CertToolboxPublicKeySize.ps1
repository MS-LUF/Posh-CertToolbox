function Get-CertToolboxPublicKeySize {
    <#
    .SYNOPSIS
        Returns the size, in bits, of a certificate's public key.
    .DESCRIPTION
        Reads the size from the encoded key itself instead of asking the runtime for a key
        object: under PowerShell 7 on Linux the key object route returned no size for an RSA
        certificate that gave 2048 on Windows, and decoding the bytes gives the same answer on
        every platform.

        RSA (1.2.840.113549.1.1.1): the key is SEQUENCE { modulus, exponent }, and the size is
        the bit length of the modulus.

        Elliptic curve (1.2.840.10045.2.1): the size is that of the named curve given in the key
        parameters, for the NIST curves P-256, P-384 and P-521; for another curve it is derived
        from the length of the encoded point.

        Any other key type gives nothing.
    .PARAMETER Certificate
        The certificate to read.
    .OUTPUTS
        System.Int32, or nothing when the size cannot be determined.
    .EXAMPLE
        Get-CertToolboxPublicKeySize -Certificate $certificate
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
    )

    try {
        $key = $Certificate.PublicKey.EncodedKeyValue.RawData

        switch ($Certificate.PublicKey.Oid.Value) {
            '1.2.840.113549.1.1.1' {
                $sequence = Read-CertToolboxDerHeader -Bytes $key -Offset 0
                $modulus = @(Get-CertToolboxDerChild -Bytes $key -Parent $sequence)[0]
                $offset = $modulus.ValueOffset
                $length = $modulus.Length
                # A leading zero byte only keeps the integer positive.
                while ($length -gt 1 -and $key[$offset] -eq 0) {
                    $offset++
                    $length--
                }
                $bits = ($length - 1) * 8
                $first = [int]$key[$offset]
                while ($first -gt 0) {
                    $bits++
                    $first = $first -shr 1
                }
                return [int]$bits
            }
            '1.2.840.10045.2.1' {
                $curve = [System.BitConverter]::ToString($Certificate.PublicKey.EncodedParameters.RawData)
                $named = @{
                    '06-08-2A-86-48-CE-3D-03-01-07' = 256   # P-256
                    '06-05-2B-81-04-00-22'          = 384   # P-384
                    '06-05-2B-81-04-00-23'          = 521   # P-521
                }[$curve]
                if ($named) {
                    return [int]$named
                }
                # Uncompressed point: one format byte, then X and Y of equal length.
                if ($key.Length -gt 1 -and $key[0] -eq 4) {
                    return [int]((($key.Length - 1) / 2) * 8)
                }
            }
        }
    } catch {
        Write-Verbose "Public key size of '$($Certificate.Subject)' could not be read: $($_.Exception.Message)"
    }
}

BeforeDiscovery {
    Import-Module (Join-Path $PSScriptRoot '../../Posh-CertToolbox.psd1') -Force
}

Describe 'Private/CertificateUrl' -Tag Unit {
    InModuleScope 'Posh-CertToolbox' {
        BeforeAll {
            . (Join-Path $PSScriptRoot '../TestHelper.ps1')
            $script:pair = Get-TestCertificateWithUrl `
                -CrlUrl 'http://crl.test.example/ca.crl', 'ldap://directory.test.example/cn=ca' `
                -OcspUrl 'http://ocsp.test.example/' `
                -CaIssuersUrl 'http://aia.test.example/ca.cer'
            $script:leafSerial = [byte[]](0x0A, 0x0B, 0x0C, 0x0D)
            $script:plain = (Get-TestCertificateChain).Leaf
        }

        Describe 'DER helpers' {
            It 'lists the children of an element and rejects one that overruns its parent' {
                $bytes = [byte[]](0x30, 0x06, 0x02, 0x01, 0x05, 0x04, 0x01, 0xFF)
                $children = @(Get-CertToolboxDerChild -Bytes $bytes -Parent (Read-CertToolboxDerHeader -Bytes $bytes -Offset 0))

                ($children.Tag -join ',') | Should -Be '2,4'
                $children[1].ValueOffset | Should -Be 7

                $broken = [byte[]](0x30, 0x04, 0x02, 0x09, 0x05, 0x04)
                { Get-CertToolboxDerChild -Bytes $broken -Parent (Read-CertToolboxDerHeader -Bytes $broken -Offset 0) } | Should -Throw
            }

            It 'reads a UTCTime with the RFC 5280 century rule and a GeneralizedTime as written' {
                $utc49 = ConvertTo-TestDer -Tag 0x17 -Content ([System.Text.Encoding]::ASCII.GetBytes('491231235959Z'))
                $utc50 = ConvertTo-TestDer -Tag 0x17 -Content ([System.Text.Encoding]::ASCII.GetBytes('500101000000Z'))
                $general = ConvertTo-TestDer -Tag 0x18 -Content ([System.Text.Encoding]::ASCII.GetBytes('20610704123456Z'))

                $a = ConvertFrom-CertToolboxDerTime -Bytes $utc49 -Header (Read-CertToolboxDerHeader -Bytes $utc49 -Offset 0)
                $b = ConvertFrom-CertToolboxDerTime -Bytes $utc50 -Header (Read-CertToolboxDerHeader -Bytes $utc50 -Offset 0)
                $c = ConvertFrom-CertToolboxDerTime -Bytes $general -Header (Read-CertToolboxDerHeader -Bytes $general -Offset 0)

                $a.Year | Should -Be 2049
                $b.Year | Should -Be 1950
                $c.ToString('yyyy-MM-dd HH:mm:ss') | Should -Be '2061-07-04 12:34:56'
                $c.Kind | Should -Be ([System.DateTimeKind]::Utc)
            }

            It 'encodes short and long lengths the way the reader decodes them' {
                foreach ($size in 0, 5, 127, 128, 255, 256, 70000) {
                    $encoded = ConvertTo-CertToolboxDerElement -Tag 0x04 -Content (New-Object byte[] $size)
                    $encoded | Should -BeOfType [byte]
                    $header = Read-CertToolboxDerHeader -Bytes $encoded -Offset 0
                    $header.Tag | Should -Be 4
                    $header.Length | Should -Be $size
                    $header.ValueOffset + $size | Should -Be $encoded.Length
                }
            }
        }

        Describe 'Get-CertToolboxCertificateUrl' {
            It 'returns the CRL, OCSP and CA Issuers URLs, each in its own list' {
                $url = Get-CertToolboxCertificateUrl -Certificate $script:pair.Leaf

                ($url.Crl -join '|') | Should -Be 'http://crl.test.example/ca.crl|ldap://directory.test.example/cn=ca'
                ($url.Ocsp -join '|') | Should -Be 'http://ocsp.test.example/'
                ($url.CaIssuers -join '|') | Should -Be 'http://aia.test.example/ca.cer'
            }

            It 'returns empty lists for a certificate without those extensions' {
                $url = Get-CertToolboxCertificateUrl -Certificate $script:plain

                $url.Crl | Should -BeNullOrEmpty
                $url.Ocsp | Should -BeNullOrEmpty
                $url.CaIssuers | Should -BeNullOrEmpty
            }
        }

        Describe 'Read-CertToolboxCrl' {
            It 'reads the dates and finds a listed serial among many entries' {
                $thisUpdate = [datetime]::new(2026, 3, 1, 10, 0, 0, [System.DateTimeKind]::Utc)
                $nextUpdate = [datetime]::new(2026, 3, 8, 10, 0, 0, [System.DateTimeKind]::Utc)
                $crl = Get-TestCrl -ThisUpdate $thisUpdate -NextUpdate $nextUpdate -PaddingEntryCount 300 -RevokedSerial (, $script:leafSerial)

                $result = Read-CertToolboxCrl -Bytes $crl -SerialNumber $script:leafSerial

                $result.ThisUpdate | Should -Be $thisUpdate
                $result.NextUpdate | Should -Be $nextUpdate
                $result.EntryCount | Should -Be 301
                $result.SerialListed | Should -BeTrue
            }

            It 'does not find a serial that is not listed' {
                $crl = Get-TestCrl -PaddingEntryCount 50 -RevokedSerial (, ([byte[]](0x0A, 0x0B, 0x0C, 0x0E)))

                (Read-CertToolboxCrl -Bytes $crl -SerialNumber $script:leafSerial).SerialListed | Should -BeFalse
            }

            It 'compares serials as numbers, ignoring a leading zero byte on either side' {
                $crl = Get-TestCrl -RevokedSerial (, ([byte[]](0x00, 0xEE, 0x1B)))
                (Read-CertToolboxCrl -Bytes $crl -SerialNumber ([byte[]](0xEE, 0x1B))).SerialListed | Should -BeTrue

                $crl = Get-TestCrl -RevokedSerial (, ([byte[]](0xEE, 0x1B)))
                (Read-CertToolboxCrl -Bytes $crl -SerialNumber ([byte[]](0x00, 0xEE, 0x1B))).SerialListed | Should -BeTrue
            }

            It 'reads an empty CRL, one without a version, one without a next update, and a far next update' {
                $empty = Read-CertToolboxCrl -Bytes (Get-TestCrl) -SerialNumber $script:leafSerial
                $empty.EntryCount | Should -Be 0
                $empty.SerialListed | Should -BeFalse

                (Read-CertToolboxCrl -Bytes (Get-TestCrl -WithoutVersion -RevokedSerial (, $script:leafSerial)) -SerialNumber $script:leafSerial).SerialListed | Should -BeTrue

                (Read-CertToolboxCrl -Bytes (Get-TestCrl -NextUpdate $null) -SerialNumber $script:leafSerial).NextUpdate | Should -BeNullOrEmpty

                $far = [datetime]::new(2061, 1, 2, 3, 4, 5, [System.DateTimeKind]::Utc)
                (Read-CertToolboxCrl -Bytes (Get-TestCrl -NextUpdate $far -GeneralizedNextUpdate) -SerialNumber $script:leafSerial).NextUpdate | Should -Be $far
            }

            It 'accepts a PEM-encoded CRL' {
                $crl = Get-TestCrl -AsPem -RevokedSerial (, $script:leafSerial)

                (Read-CertToolboxCrl -Bytes $crl -SerialNumber $script:leafSerial).SerialListed | Should -BeTrue
            }

            It 'throws on data that is not a CRL' {
                { Read-CertToolboxCrl -Bytes ([System.Text.Encoding]::ASCII.GetBytes('<html>not found</html>')) -SerialNumber $script:leafSerial } | Should -Throw
                { Read-CertToolboxCrl -Bytes ([System.Text.Encoding]::ASCII.GetBytes('-----BEGIN CERTIFICATE-----')) -SerialNumber $script:leafSerial } | Should -Throw '*neither a DER nor a PEM*'
            }
        }

        Describe 'ConvertTo-CertToolboxOcspRequest' {
            It 'identifies the certificate by issuer name hash, issuer key hash and serial' {
                $request = ConvertTo-CertToolboxOcspRequest -Certificate $script:pair.Leaf -Issuer $script:pair.Issuer

                # OCSPRequest { tbsRequest { requestList { Request { CertID { alg, nameHash, keyHash, serial } } } } }
                $node = Read-CertToolboxDerHeader -Bytes $request -Offset 0
                $node.ValueOffset + $node.Length | Should -Be $request.Length
                foreach ($level in 1..4) {
                    $node = @(Get-CertToolboxDerChild -Bytes $request -Parent $node)[0]
                    $node.Tag | Should -Be 0x30
                }
                $part = @(Get-CertToolboxDerChild -Bytes $request -Parent $node)
                ($part.Tag -join ',') | Should -Be '48,4,4,2'

                $sha1 = [System.Security.Cryptography.SHA1]::Create()
                $expectedName = [System.BitConverter]::ToString($sha1.ComputeHash($script:pair.Leaf.IssuerName.RawData))
                $expectedKey = [System.BitConverter]::ToString($sha1.ComputeHash($script:pair.Issuer.PublicKey.EncodedKeyValue.RawData))

                [System.BitConverter]::ToString($request, $part[0].ValueOffset, $part[0].Length) | Should -Be '06-05-2B-0E-03-02-1A-05-00'
                [System.BitConverter]::ToString($request, $part[1].ValueOffset, $part[1].Length) | Should -Be $expectedName
                [System.BitConverter]::ToString($request, $part[2].ValueOffset, $part[2].Length) | Should -Be $expectedKey
                [System.BitConverter]::ToString($request, $part[3].ValueOffset, $part[3].Length) | Should -Be '0A-0B-0C-0D'
            }
        }

        Describe 'ConvertFrom-CertToolboxOcspResponse' {
            It 'reads a successful response for a <Status> certificate' -ForEach @(
                @{ Status = 'Good' }, @{ Status = 'Revoked' }, @{ Status = 'Unknown' }
            ) {
                $thisUpdate = [datetime]::new(2026, 5, 1, 8, 0, 0, [System.DateTimeKind]::Utc)
                $nextUpdate = [datetime]::new(2026, 5, 8, 8, 0, 0, [System.DateTimeKind]::Utc)
                $produced = [datetime]::new(2026, 5, 1, 9, 30, 0, [System.DateTimeKind]::Utc)
                $bytes = Get-TestOcspResponse -CertificateStatus $Status -ThisUpdate $thisUpdate -NextUpdate $nextUpdate -ProducedAt $produced

                $result = ConvertFrom-CertToolboxOcspResponse -Bytes $bytes

                $result.ResponseStatus | Should -Be 'Successful'
                $result.CertificateStatus | Should -Be $Status
                $result.ProducedAt | Should -Be $produced
                $result.ThisUpdate | Should -Be $thisUpdate
                $result.NextUpdate | Should -Be $nextUpdate
            }

            It 'reads a response that carries an explicit version and no next update' {
                $result = ConvertFrom-CertToolboxOcspResponse -Bytes (Get-TestOcspResponse -WithVersion -NextUpdate $null)

                $result.CertificateStatus | Should -Be 'Good'
                $result.NextUpdate | Should -BeNullOrEmpty
            }

            It 'reports a responder error by name, with no certificate status' {
                $result = ConvertFrom-CertToolboxOcspResponse -Bytes (Get-TestOcspResponse -ResponseStatus 6)
                $result.ResponseStatus | Should -Be 'Unauthorized'
                $result.CertificateStatus | Should -BeNullOrEmpty

                (ConvertFrom-CertToolboxOcspResponse -Bytes (Get-TestOcspResponse -ResponseStatus 3)).ResponseStatus | Should -Be 'TryLater'
            }

            It 'throws on data that is not an OCSP response' {
                { ConvertFrom-CertToolboxOcspResponse -Bytes ([System.Text.Encoding]::ASCII.GetBytes('<html>error</html>')) } | Should -Throw
            }
        }

        Describe 'Test-CertToolboxIssuerCertificate' {
            It 'matches the issuer returned as a DER certificate' {
                $result = Test-CertToolboxIssuerCertificate -Bytes $script:pair.Issuer.RawData -Certificate $script:pair.Leaf

                $result.IsCertificate | Should -BeTrue
                $result.Match | Should -BeTrue
                $result.Subject | Should -Be 'CN=CertToolbox Url Test CA'
            }

            It 'matches the issuer returned as PEM' {
                $pem = "-----BEGIN CERTIFICATE-----`n" + [System.Convert]::ToBase64String($script:pair.Issuer.RawData, 'InsertLineBreaks') + "`n-----END CERTIFICATE-----`n"

                (Test-CertToolboxIssuerCertificate -Bytes ([System.Text.Encoding]::ASCII.GetBytes($pem)) -Certificate $script:pair.Leaf).Match | Should -BeTrue
            }

            It 'reports a certificate that is not the issuer' {
                $result = Test-CertToolboxIssuerCertificate -Bytes $script:plain.RawData -Certificate $script:pair.Leaf

                $result.IsCertificate | Should -BeTrue
                $result.Match | Should -BeFalse
            }

            It 'reports data that is not a certificate' {
                $result = Test-CertToolboxIssuerCertificate -Bytes ([System.Text.Encoding]::ASCII.GetBytes('<html>not found</html>')) -Certificate $script:pair.Leaf

                $result.IsCertificate | Should -BeFalse
                $result.Match | Should -BeFalse
            }
        }

        # A real HTTP server on the loopback interface, in a background runspace: this checks
        # the bytes and headers actually exchanged, on the runtime under test.
        Describe 'Invoke-CertToolboxHttpRequest' {
            BeforeAll {
                $script:server = Start-TestHttpServer
            }

            AfterAll {
                Stop-TestHttpServer -Server $script:server
            }

            It 'returns the response body as a byte array' {
                $bytes = Invoke-CertToolboxHttpRequest -Uri "$($script:server.Prefix)ok"

                , $bytes | Should -BeOfType [byte[]]
                ($bytes -join ',') | Should -Be '1,2,3,4,5'
            }

            It 'posts a binary body with its content type and asks for an uncached answer' {
                $body = [byte[]](0x30, 0x03, 0x01, 0x02, 0x03)

                $bytes = Invoke-CertToolboxHttpRequest -Uri "$($script:server.Prefix)echo" -Method Post -Body $body -ContentType 'application/ocsp-request'

                $head = [System.Text.Encoding]::ASCII.GetBytes('POST|application/ocsp-request|no-cache|')
                [System.Text.Encoding]::ASCII.GetString($bytes, 0, $head.Length) | Should -Be 'POST|application/ocsp-request|no-cache|'
                [System.BitConverter]::ToString($bytes, $head.Length) | Should -Be '30-03-01-02-03'
            }

            It 'throws with the status on an HTTP error' {
                { Invoke-CertToolboxHttpRequest -Uri "$($script:server.Prefix)missing" } | Should -Throw '*HTTP 404*'
            }

            It 'throws when the response is larger than accepted' {
                { Invoke-CertToolboxHttpRequest -Uri "$($script:server.Prefix)big" -MaxBytes 1000 } | Should -Throw '*1000 bytes accepted*'
                (Invoke-CertToolboxHttpRequest -Uri "$($script:server.Prefix)big" -MaxBytes 5000).Length | Should -Be 5000
            }

            It 'throws a timeout when the server does not answer in time' {
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

                { Invoke-CertToolboxHttpRequest -Uri "$($script:server.Prefix)slow" -TimeoutSec 1 } |
                    Should -Throw -ExceptionType ([System.TimeoutException])

                $stopwatch.ElapsedMilliseconds | Should -BeLessThan 3500
            }
        }

        Describe 'Invoke-CertToolboxCertificateUrlTest' {
            BeforeEach {
                $script:goodCrl = Get-TestCrl -PaddingEntryCount 3
                $script:revokedCrl = Get-TestCrl -RevokedSerial (, $script:leafSerial)
                $script:expiredCrl = Get-TestCrl -ThisUpdate ([datetime]::UtcNow.AddDays(-20)) -NextUpdate ([datetime]::UtcNow.AddDays(-10))
                $script:goodOcsp = Get-TestOcspResponse -CertificateStatus Good
                $script:issuerBytes = $script:pair.Issuer.RawData

                Mock Invoke-CertToolboxHttpRequest { , $script:goodCrl } -ParameterFilter { $Uri.Host -eq 'crl.test.example' }
                Mock Invoke-CertToolboxHttpRequest { , $script:goodOcsp } -ParameterFilter { $Uri.Host -eq 'ocsp.test.example' }
                Mock Invoke-CertToolboxHttpRequest { , $script:issuerBytes } -ParameterFilter { $Uri.Host -eq 'aia.test.example' }
            }

            It 'returns one row per URL of the leaf, and none for a certificate without URLs' {
                $rows = @(Invoke-CertToolboxCertificateUrlTest -ServerCertificate $script:pair.Leaf, $script:pair.Issuer `
                        -LocalCertificate $script:pair.Leaf, $script:pair.Issuer)

                $rows.Count | Should -Be 4
                $rows[0].PSObject.TypeNames[0] | Should -Be 'CertToolbox.CertificateUrlTest'
                ($rows.Type -join ',') | Should -Be 'Crl,Crl,Ocsp,CaIssuers'
                @($rows | Where-Object { $_.Thumbprint -ne $script:pair.Leaf.Thumbprint }) | Should -BeNullOrEmpty
                @($rows | Where-Object { $_.Chain -ne 'Both' }) | Should -BeNullOrEmpty
            }

            It 'reports a healthy CRL, OCSP responder and issuer URL' {
                $rows = @(Invoke-CertToolboxCertificateUrlTest -ServerCertificate $script:pair.Leaf, $script:pair.Issuer -LocalCertificate @())

                $crl = $rows | Where-Object { $_.Type -eq 'Crl' -and $_.Url -like 'http*' }
                $crl.Result | Should -Be 'NotRevoked'
                $crl.Reachable | Should -BeTrue
                $crl.NextUpdate | Should -BeGreaterThan ([datetime]::UtcNow)
                $crl.Detail | Should -BeLike '3 revoked certificate(s) listed*'

                $ocsp = $rows | Where-Object Type -eq 'Ocsp'
                $ocsp.Result | Should -Be 'Good'
                $ocsp.ThisUpdate | Should -Not -BeNullOrEmpty

                $issuer = $rows | Where-Object Type -eq 'CaIssuers'
                $issuer.Result | Should -Be 'IssuerMatch'
                $issuer.Detail | Should -Be 'CN=CertToolbox Url Test CA'
            }

            It 'sends the OCSP request as a POST with the right content type and body' {
                Invoke-CertToolboxCertificateUrlTest -ServerCertificate $script:pair.Leaf, $script:pair.Issuer -LocalCertificate @() | Out-Null

                $expected = [System.Convert]::ToBase64String((ConvertTo-CertToolboxOcspRequest -Certificate $script:pair.Leaf -Issuer $script:pair.Issuer))
                Should -Invoke Invoke-CertToolboxHttpRequest -Times 1 -Exactly -ParameterFilter {
                    $Uri.Host -eq 'ocsp.test.example' -and $Method -eq 'Post' -and $ContentType -eq 'application/ocsp-request' -and
                    [System.Convert]::ToBase64String($Body) -eq $expected
                }
            }

            It 'skips a URL that is not http or https, without requesting it' {
                $rows = @(Invoke-CertToolboxCertificateUrlTest -ServerCertificate $script:pair.Leaf, $script:pair.Issuer -LocalCertificate @())

                $ldap = $rows | Where-Object { $_.Url -like 'ldap:*' }
                $ldap.Result | Should -Be 'Skipped'
                $ldap.Reachable | Should -BeNullOrEmpty
                $ldap.Detail | Should -BeLike '*http and https*'
                Should -Invoke Invoke-CertToolboxHttpRequest -Times 0 -Exactly -ParameterFilter { $Uri.Scheme -eq 'ldap' }
            }

            It 'reports a revoked certificate and an expired CRL' {
                Mock Invoke-CertToolboxHttpRequest { , $script:revokedCrl } -ParameterFilter { $Uri.Host -eq 'crl.test.example' }
                $rows = @(Invoke-CertToolboxCertificateUrlTest -ServerCertificate $script:pair.Leaf -LocalCertificate @())
                ($rows | Where-Object { $_.Type -eq 'Crl' -and $_.Url -like 'http*' }).Result | Should -Be 'Revoked'

                Mock Invoke-CertToolboxHttpRequest { , $script:expiredCrl } -ParameterFilter { $Uri.Host -eq 'crl.test.example' }
                $rows = @(Invoke-CertToolboxCertificateUrlTest -ServerCertificate $script:pair.Leaf -LocalCertificate @())
                ($rows | Where-Object { $_.Type -eq 'Crl' -and $_.Url -like 'http*' }).Result | Should -Be 'CrlExpired'
            }

            It 'reports what the OCSP responder answered: <Expected>' -ForEach @(
                @{ Expected = 'Revoked'; Response = { Get-TestOcspResponse -CertificateStatus Revoked } }
                @{ Expected = 'Unknown'; Response = { Get-TestOcspResponse -CertificateStatus Unknown } }
                @{ Expected = 'ResponderError'; Response = { Get-TestOcspResponse -ResponseStatus 6 } }
            ) {
                $script:ocspBytes = & $Response
                Mock Invoke-CertToolboxHttpRequest { , $script:ocspBytes } -ParameterFilter { $Uri.Host -eq 'ocsp.test.example' }

                $row = Invoke-CertToolboxCertificateUrlTest -ServerCertificate $script:pair.Leaf, $script:pair.Issuer -LocalCertificate @() |
                    Where-Object Type -eq 'Ocsp'

                $row.Result | Should -Be $Expected
                $row.Reachable | Should -BeTrue
            }

            It 'skips OCSP when the issuer certificate is in neither chain, and finds it in the other chain otherwise' {
                $alone = Invoke-CertToolboxCertificateUrlTest -ServerCertificate $script:pair.Leaf -LocalCertificate @() |
                    Where-Object Type -eq 'Ocsp'
                $alone.Result | Should -Be 'Skipped'
                $alone.Detail | Should -BeLike '*issuer certificate*neither chain*'
                Should -Invoke Invoke-CertToolboxHttpRequest -Times 0 -Exactly -ParameterFilter { $Uri.Host -eq 'ocsp.test.example' }

                # The server sent only its leaf; the local chain supplies the issuer.
                $rows = @(Invoke-CertToolboxCertificateUrlTest -ServerCertificate $script:pair.Leaf -LocalCertificate $script:pair.Leaf, $script:pair.Issuer)
                ($rows | Where-Object Type -eq 'Ocsp').Result | Should -Be 'Good'
            }

            It 'labels each certificate with the chain it belongs to and tests a shared one once' {
                $serverOnly = Get-TestCertificateWithUrl -CrlUrl 'http://crl.test.example/server.crl' -SerialNumber ([byte[]](1, 1))
                $localOnly = Get-TestCertificateWithUrl -CrlUrl 'http://crl.test.example/local.crl' -SerialNumber ([byte[]](2, 2))

                $rows = @(Invoke-CertToolboxCertificateUrlTest `
                        -ServerCertificate $script:pair.Leaf, $serverOnly.Leaf `
                        -LocalCertificate $script:pair.Leaf, $localOnly.Leaf)

                ($rows | Where-Object { $_.Url -like '*server.crl' }).Chain | Should -Be 'Server'
                ($rows | Where-Object { $_.Url -like '*local.crl' }).Chain | Should -Be 'Local'
                @($rows | Where-Object { $_.Thumbprint -eq $script:pair.Leaf.Thumbprint -and $_.Type -eq 'CaIssuers' }).Count | Should -Be 1
                Should -Invoke Invoke-CertToolboxHttpRequest -Times 1 -Exactly -ParameterFilter { $Uri.AbsoluteUri -eq 'http://crl.test.example/ca.crl' }
            }

            It 'requests a URL shared by two certificates only once' {
                $first = Get-TestCertificateWithUrl -CrlUrl 'http://crl.test.example/shared.crl' -SerialNumber ([byte[]](1, 1))
                $second = Get-TestCertificateWithUrl -CrlUrl 'http://crl.test.example/shared.crl' -SerialNumber ([byte[]](2, 2))

                $rows = @(Invoke-CertToolboxCertificateUrlTest -ServerCertificate $first.Leaf, $second.Leaf -LocalCertificate @())

                $rows.Count | Should -Be 2
                Should -Invoke Invoke-CertToolboxHttpRequest -Times 1 -Exactly -ParameterFilter { $Uri.AbsoluteUri -eq 'http://crl.test.example/shared.crl' }
            }

            It 'reports an unreachable URL as Failed with the error, and carries on with the others' {
                Mock Invoke-CertToolboxHttpRequest { throw [System.Net.Http.HttpRequestException]::new('HTTP 404 Not Found') } -ParameterFilter { $Uri.Host -eq 'crl.test.example' }

                $rows = @(Invoke-CertToolboxCertificateUrlTest -ServerCertificate $script:pair.Leaf, $script:pair.Issuer -LocalCertificate @())

                $crl = $rows | Where-Object { $_.Type -eq 'Crl' -and $_.Url -like 'http*' }
                $crl.Result | Should -Be 'Failed'
                $crl.Reachable | Should -BeFalse
                $crl.Detail | Should -Be 'HTTP 404 Not Found'
                ($rows | Where-Object Type -eq 'Ocsp').Result | Should -Be 'Good'
            }

            It 'reports an answer it cannot read as Failed, and a wrong or missing issuer certificate' {
                $script:junk = [System.Text.Encoding]::ASCII.GetBytes('<html>maintenance</html>')
                Mock Invoke-CertToolboxHttpRequest { , $script:junk } -ParameterFilter { $Uri.Host -in 'crl.test.example', 'ocsp.test.example', 'aia.test.example' }

                $rows = @(Invoke-CertToolboxCertificateUrlTest -ServerCertificate $script:pair.Leaf, $script:pair.Issuer -LocalCertificate @())

                $crl = $rows | Where-Object { $_.Type -eq 'Crl' -and $_.Url -like 'http*' }
                $crl.Result | Should -Be 'Failed'
                $crl.Reachable | Should -BeTrue
                $crl.Detail | Should -BeLike 'The answer could not be read*'
                ($rows | Where-Object Type -eq 'Ocsp').Result | Should -Be 'Failed'
                ($rows | Where-Object Type -eq 'CaIssuers').Result | Should -Be 'NotACertificate'

                $script:otherCertificate = $script:plain.RawData
                Mock Invoke-CertToolboxHttpRequest { , $script:otherCertificate } -ParameterFilter { $Uri.Host -eq 'aia.test.example' }
                (Invoke-CertToolboxCertificateUrlTest -ServerCertificate $script:pair.Leaf -LocalCertificate @() |
                    Where-Object Type -eq 'CaIssuers').Result | Should -Be 'IssuerMismatch'
            }

            It 'passes the timeout to every request and returns nothing for empty chains' {
                Invoke-CertToolboxCertificateUrlTest -ServerCertificate $script:pair.Leaf, $script:pair.Issuer -LocalCertificate @() -TimeoutSec 3 | Out-Null
                Should -Invoke Invoke-CertToolboxHttpRequest -Times 3 -Exactly -ParameterFilter { $TimeoutSec -eq 3 }

                Invoke-CertToolboxCertificateUrlTest -ServerCertificate @() -LocalCertificate @() | Should -BeNullOrEmpty
            }
        }
    }
}

function Invoke-CertToolboxHttpRequest {
    <#
    .SYNOPSIS
        Sends one HTTP request and returns the response body as bytes.
    .DESCRIPTION
        The single HTTP entry point for downloading CRLs and issuer certificates and for
        querying OCSP responders, so that tests can mock it.

        Built on HttpClient rather than Invoke-WebRequest: the body is binary, it has to be
        bounded in size while it is being read (a CRL can be very large), and the same code must
        behave identically under Windows PowerShell 5.1 and PowerShell 7. The assembly is loaded
        first under 5.1, where it is not preloaded.

        The timeout covers the whole exchange, body included. Throws on a status other than
        2xx, on a body larger than MaxBytes and on a timeout; the message says which.
    .PARAMETER Uri
        The http or https URL to request.
    .PARAMETER Method
        Get (the default) or Post.
    .PARAMETER Body
        Request body, for Post.
    .PARAMETER ContentType
        Media type of the request body.
    .PARAMETER TimeoutSec
        Time allowed for the whole exchange, in seconds.
    .PARAMETER MaxBytes
        Largest response body accepted.
    .OUTPUTS
        System.Byte[]
    .EXAMPLE
        Invoke-CertToolboxHttpRequest -Uri 'http://crl.example.com/ca.crl'
    #>
    [CmdletBinding()]
    [OutputType([byte[]], [System.Array])]
    param(
        [Parameter(Mandatory)]
        [uri] $Uri,

        [Parameter()]
        [ValidateSet('Get', 'Post')]
        [string] $Method = 'Get',

        [Parameter()]
        [byte[]] $Body,

        [Parameter()]
        [string] $ContentType,

        [Parameter()]
        [int] $TimeoutSec = 10,

        [Parameter()]
        [long] $MaxBytes = $script:CertToolboxMaxDownloadBytes
    )

    if (-not ('System.Net.Http.HttpClient' -as [type])) {
        Add-Type -AssemblyName System.Net.Http
    }

    $client = [System.Net.Http.HttpClient]::new()
    $cancellation = [System.Threading.CancellationTokenSource]::new([System.TimeSpan]::FromSeconds($TimeoutSec))
    $request = $null
    $response = $null
    $buffer = [System.IO.MemoryStream]::new()
    try {
        # The token below bounds the exchange; the client's own timeout would only cover it up
        # to the response headers.
        $client.Timeout = [System.Threading.Timeout]::InfiniteTimeSpan

        $httpMethod = [System.Net.Http.HttpMethod]::Get
        if ($Method -eq 'Post') {
            $httpMethod = [System.Net.Http.HttpMethod]::Post
        }
        $request = [System.Net.Http.HttpRequestMessage]::new($httpMethod, $Uri)
        $null = $request.Headers.TryAddWithoutValidation('Cache-Control', 'no-cache')
        $null = $request.Headers.TryAddWithoutValidation('User-Agent', 'Posh-CertToolbox')

        if ($Body) {
            $request.Content = [System.Net.Http.ByteArrayContent]::new([byte[]]$Body)
            if ($ContentType) {
                $request.Content.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::new($ContentType)
            }
        }

        Write-Verbose "HTTP $($Method.ToUpperInvariant()) $Uri"
        $response = $client.SendAsync($request, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cancellation.Token).GetAwaiter().GetResult()

        if (-not $response.IsSuccessStatusCode) {
            throw [System.Net.Http.HttpRequestException]::new("HTTP $([int]$response.StatusCode) $($response.ReasonPhrase)".Trim())
        }

        $announced = $response.Content.Headers.ContentLength
        if ($null -ne $announced -and $announced -gt $MaxBytes) {
            throw [System.IO.InvalidDataException]::new("The response is $announced bytes, more than the $MaxBytes bytes accepted.")
        }

        $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $chunk = New-Object byte[] 81920
        while ($true) {
            $read = $stream.ReadAsync($chunk, 0, $chunk.Length, $cancellation.Token).GetAwaiter().GetResult()
            if ($read -le 0) {
                break
            }
            $buffer.Write($chunk, 0, $read)
            if ($buffer.Length -gt $MaxBytes) {
                throw [System.IO.InvalidDataException]::new("The response is larger than the $MaxBytes bytes accepted.")
            }
        }

        , $buffer.ToArray()
    } catch {
        # The token is the only thing that cancels this exchange, so a cancelled token means the
        # time ran out, whatever exception the runtime surfaced for it (it differs: a cancelled
        # task under 5.1, an aborted socket operation under 7).
        if ($cancellation.IsCancellationRequested) {
            throw [System.TimeoutException]::new("No complete answer within $TimeoutSec seconds.")
        }
        throw (Resolve-CertToolboxException -Exception $_.Exception)
    } finally {
        if ($response) { $response.Dispose() }
        if ($request) { $request.Dispose() }
        $buffer.Dispose()
        $cancellation.Dispose()
        $client.Dispose()
    }
}

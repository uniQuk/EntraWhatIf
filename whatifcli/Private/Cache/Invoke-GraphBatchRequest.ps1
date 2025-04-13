function Invoke-GraphBatchRequest {
    <#
    .SYNOPSIS
        Executes multiple Microsoft Graph API requests in a single batch.

    .DESCRIPTION
        This function combines multiple Graph API requests into a single batch request,
        reducing the number of network calls and improving performance. Each request
        can have its own method, URL, and optional body.

    .PARAMETER Requests
        An array of request objects, each containing Id, Method, Url, and optionally Body.

    .EXAMPLE
        $requests = @(
            @{
                Id = "1"
                Method = "GET"
                Url = "/users/user1@example.com"
            },
            @{
                Id = "2"
                Method = "GET"
                Url = "/users/user2@example.com"
            }
        )

        $responses = Invoke-GraphBatchRequest -Requests $requests

    .NOTES
        This function is limited to a maximum of 20 requests per batch as per Microsoft Graph API limits.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$Requests
    )

    # Microsoft Graph API limits batch requests to 20 requests
    if ($Requests.Count -gt 20) {
        Write-Warning "Batch request contains more than 20 requests. Microsoft Graph API limits batch requests to 20 requests."
        $Requests = $Requests[0..19]
    }

    # Construct the batch request
    $batchRequest = @{
        requests = $Requests | ForEach-Object {
            $request = @{
                id     = $_.Id
                method = $_.Method
                url    = $_.Url.TrimStart('/')  # Ensure URL doesn't start with /
            }

            # Add body if present
            if ($_.Body) {
                $request.body = $_.Body
            }

            # Add headers if present
            if ($_.Headers) {
                $request.headers = $_.Headers
            }

            $request
        }
    }

    try {
        # Execute the batch request
        $response = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/`$batch" -Body ($batchRequest | ConvertTo-Json -Depth 10)

        # Log diagnostics
        Write-DiagnosticOutput -Source "Invoke-GraphBatchRequest" -Message "Batch request executed with $($Requests.Count) requests" -Level "Info"

        # Return the responses
        return $response.responses
    }
    catch {
        Write-DiagnosticOutput -Source "Invoke-GraphBatchRequest" -Message "Batch request failed: $_" -Level "Error"
        throw $_
    }
}

Export-ModuleMember -Function Invoke-GraphBatchRequest
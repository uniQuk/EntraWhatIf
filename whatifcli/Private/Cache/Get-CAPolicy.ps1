function Get-CAPolicy {
    <#
    .SYNOPSIS
        Retrieves Conditional Access policies from Microsoft Graph.

    .DESCRIPTION
        Retrieves Conditional Access policies from Microsoft Graph, with optional filtering by policy IDs.
        Uses query parameter optimization, batch processing, and centralized caching for improved performance.

    .PARAMETER PolicyIds
        The IDs of specific policies to retrieve. If not specified, all policies are retrieved.

    .PARAMETER IncludeReportOnly
        Whether to include policies in report-only mode in the results.

    .PARAMETER UseBatchProcessing
        Whether to use batch processing for retrieving multiple policies. This is more efficient
        when retrieving multiple specific policies.

    .PARAMETER ForceRefresh
        Forces a refresh of the policy cache.

    .EXAMPLE
        Get-CAPolicy

    .EXAMPLE
        Get-CAPolicy -PolicyIds "policy1", "policy2" -IncludeReportOnly -UseBatchProcessing
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]$PolicyIds,

        [Parameter()]
        [switch]$IncludeReportOnly,

        [Parameter()]
        [switch]$UseBatchProcessing,

        [Parameter()]
        [switch]$ForceRefresh
    )

    try {
        # Select fields to optimize data retrieval
        $select = "id,displayName,state,conditions,grantControls,sessionControls"

        # If force refresh is set, clear the policy cache
        if ($ForceRefresh) {
            Write-DiagnosticOutput -Source "Get-CAPolicy" -Message "Forcing policy cache refresh" -Level "Info"
            Get-CacheManager -Operation Clear -CacheType Policies
        }

        # Check if we need to get all policies
        if (-not $PolicyIds) {
            # Try to get cached "all policies" collection
            $allPolicies = Get-CacheManager -Operation Get -CacheType Policies -Key "AllPolicies"

            if (-not $allPolicies) {
                Write-DiagnosticOutput -Source "Get-CAPolicy" -Message "Retrieving all policies from Microsoft Graph" -Level "Info"

                # Retrieve all policies with optimized query
                $allPolicies = Get-MgIdentityConditionalAccessPolicy -Select $select

                # Cache the policies
                Get-CacheManager -Operation Set -CacheType Policies -Key "AllPolicies" -Value $allPolicies

                # Also cache individual policies for direct lookups
                foreach ($policy in $allPolicies) {
                    Get-CacheManager -Operation Set -CacheType Policies -Key $policy.Id -Value $policy
                }
            }

            # Filter by state if IncludeReportOnly is not specified
            if (-not $IncludeReportOnly) {
                return $allPolicies | Where-Object { $_.State -ne "enabledForReportingButNotEnforced" }
            }
            else {
                return $allPolicies
            }
        }

        # If we're looking for specific policies
        $filteredPolicies = @()
        $uncachedPolicyIds = @()

        # Check cache for each requested policy
        foreach ($policyId in $PolicyIds) {
            $policy = Get-CacheManager -Operation Get -CacheType Policies -Key $policyId

            if ($policy) {
                $filteredPolicies += $policy
            }
            else {
                $uncachedPolicyIds += $policyId
            }
        }

        # If there are uncached policies, retrieve them
        if ($uncachedPolicyIds.Count -gt 0) {
            if ($UseBatchProcessing -and $uncachedPolicyIds.Count -gt 1) {
                Write-DiagnosticOutput -Source "Get-CAPolicy" -Message "Using batch processing for retrieving $($uncachedPolicyIds.Count) policies" -Level "Info"

                # Create batch requests
                $batchRequests = @()

                for ($i = 0; $i -lt $uncachedPolicyIds.Count; $i++) {
                    # Construct URL without string concatenation
                    $url = "/identity/conditionalAccess/policies/$($uncachedPolicyIds[$i])?`$select=$select"

                    $batchRequests += @{
                        Id     = "request-$i"
                        Method = "GET"
                        Url    = $url
                    }
                }

                # Execute batch request
                $batchResponses = Invoke-GraphBatchRequest -Requests $batchRequests

                # Process responses and update cache
                for ($i = 0; $i -lt $batchResponses.Count; $i++) {
                    $response = $batchResponses[$i]
                    if ($response.status -eq 200) {
                        $policy = $response.body
                        $filteredPolicies += $policy

                        # Cache the policy
                        Get-CacheManager -Operation Set -CacheType Policies -Key $policy.id -Value $policy
                    }
                    else {
                        Write-DiagnosticOutput -Source "Get-CAPolicy" -Message "Failed to retrieve policy: $($response.error.message)" -Level "Warning"
                    }
                }
            }
            else {
                # Get policies individually
                foreach ($policyId in $uncachedPolicyIds) {
                    try {
                        $policy = Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policyId -Select $select
                        $filteredPolicies += $policy

                        # Cache the policy
                        Get-CacheManager -Operation Set -CacheType Policies -Key $policy.Id -Value $policy
                    }
                    catch {
                        Write-DiagnosticOutput -Source "Get-CAPolicy" -Message "Failed to retrieve policy {$policyId}: $_" -Level "Warning"
                    }
                }
            }
        }

        # Filter by state if IncludeReportOnly is not specified
        if (-not $IncludeReportOnly) {
            return $filteredPolicies | Where-Object { $_.State -ne "enabledForReportingButNotEnforced" }
        }
        else {
            return $filteredPolicies
        }
    }
    catch {
        Write-DiagnosticOutput -Source "Get-CAPolicy" -Message "Failed to retrieve Conditional Access policies: $_" -Level "Error"
        throw $_
    }
}
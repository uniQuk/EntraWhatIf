function Get-CAPolicy {
    <#
    .SYNOPSIS
        Retrieves Conditional Access policies from Microsoft Graph.
    
    .DESCRIPTION
        Retrieves Conditional Access policies from Microsoft Graph, with optional filtering by policy IDs.
    
    .PARAMETER PolicyIds
        The IDs of specific policies to retrieve. If not specified, all policies are retrieved.
    
    .PARAMETER IncludeReportOnly
        Whether to include policies in report-only mode in the results.
    
    .EXAMPLE
        Get-CAPolicy
    
    .EXAMPLE
        Get-CAPolicy -PolicyIds "policy1", "policy2" -IncludeReportOnly
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]$PolicyIds,
        
        [Parameter()]
        [switch]$IncludeReportOnly
    )
    
    try {
        # Check if policies are already cached
        if ($script:CAPolicies.Count -eq 0) {
            Write-Verbose "Retrieving Conditional Access policies from Microsoft Graph"
            $script:CAPolicies = Get-MgIdentityConditionalAccessPolicy
        }
        
        # Filter by policy IDs if specified
        if ($PolicyIds) {
            $filteredPolicies = $script:CAPolicies | Where-Object { $_.Id -in $PolicyIds }
        } else {
            $filteredPolicies = $script:CAPolicies
        }
        
        # Filter by state if IncludeReportOnly is not specified
        if (-not $IncludeReportOnly) {
            $filteredPolicies = $filteredPolicies | Where-Object { $_.State -ne "enabledForReportingButNotEnforced" }
        }
        
        return $filteredPolicies
    }
    catch {
        Write-Error "Failed to retrieve Conditional Access policies: $_"
        return $null
    }
} 
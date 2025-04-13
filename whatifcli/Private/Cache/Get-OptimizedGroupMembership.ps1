function Get-OptimizedGroupMembership {
    <#
    .SYNOPSIS
        Retrieves group memberships for users in a highly optimized manner.

    .DESCRIPTION
        This function retrieves group memberships for users using batch processing and caching
        to minimize API calls and improve performance.

    .PARAMETER UserId
        The ID of the user to retrieve group memberships for.

    .PARAMETER ServicePrincipalId
        The ID of the service principal to retrieve group memberships for.

    .PARAMETER GroupIds
        Optional array of specific group IDs to check membership for. If not provided,
        all group memberships will be retrieved.

    .PARAMETER IncludeNestedGroups
        Whether to include transitive group memberships (nested groups).
        Always true when using the optimized function as it uses transitiveMemberOf.

    .PARAMETER ForceRefresh
        Forces a refresh of the cache for the specified user or service principal.

    .EXAMPLE
        Get-OptimizedGroupMembership -UserId "12345678-1234-1234-1234-123456789012"

    .EXAMPLE
        Get-OptimizedGroupMembership -ServicePrincipalId "87654321-4321-4321-4321-210987654321" -GroupIds @("group1", "group2")
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$UserId,

        [Parameter(Mandatory = $false)]
        [string]$ServicePrincipalId,

        [Parameter(Mandatory = $false)]
        [string[]]$GroupIds,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeNestedGroups = $true,

        [Parameter(Mandatory = $false)]
        [switch]$ForceRefresh
    )

    # Initialize cache if it doesn't exist
    if (-not (Get-Variable -Name GroupMembershipCache -Scope Script -ErrorAction SilentlyContinue)) {
        $script:GroupMembershipCache = @{}
        $script:GroupMembershipCacheTime = @{}
    }

    # Define cache expiration (15 minutes)
    $cacheExpiration = [TimeSpan]::FromMinutes(15)

    # Determine the entity ID (either user or service principal)
    $entityId = if ($UserId) { $UserId } else { $ServicePrincipalId }
    $entityType = if ($UserId) { "user" } else { "servicePrincipal" }

    if (-not $entityId) {
        Write-DiagnosticOutput -Source "Get-OptimizedGroupMembership" -Message "Either UserId or ServicePrincipalId must be specified" -Level "Error"
        throw "Either UserId or ServicePrincipalId must be specified"
    }

    # Check if cache needs refreshing
    $cacheKey = "$entityType-$entityId"
    $cacheExpired = $false

    if ($script:GroupMembershipCacheTime.ContainsKey($cacheKey)) {
        $cacheExpired = ([DateTime]::Now - $script:GroupMembershipCacheTime[$cacheKey]) -gt $cacheExpiration
    }

    # Refresh cache if needed
    if ($ForceRefresh -or $cacheExpired -or -not $script:GroupMembershipCache.ContainsKey($cacheKey)) {
        Write-DiagnosticOutput -Source "Get-OptimizedGroupMembership" -Message "Refreshing group membership cache for $entityType $entityId" -Level "Info"

        try {
            $groups = @()

            if ($entityType -eq "user") {
                # Use transitive member of to get all groups (direct and nested)
                $uri = "/users/$entityId/transitiveMemberOf?`$select=id,displayName"
                $groups = Invoke-MgGraphRequest -Method GET -Uri $uri | Select-Object -ExpandProperty value
            }
            else {
                # For service principals
                $uri = "/servicePrincipals/$entityId/transitiveMemberOf?`$select=id,displayName"
                $groups = Invoke-MgGraphRequest -Method GET -Uri $uri | Select-Object -ExpandProperty value
            }

            # Update cache
            $script:GroupMembershipCache[$cacheKey] = $groups
            $script:GroupMembershipCacheTime[$cacheKey] = [DateTime]::Now
        }
        catch {
            Write-DiagnosticOutput -Source "Get-OptimizedGroupMembership" -Message "Failed to retrieve group memberships: $_" -Level "Error"
            throw $_
        }
    }

    # Return all groups or filter by specified group IDs
    $memberOf = $script:GroupMembershipCache[$cacheKey]

    if ($GroupIds -and $GroupIds.Count -gt 0) {
        return $memberOf | Where-Object { $_.id -in $GroupIds }
    }
    else {
        return $memberOf
    }
}

Export-ModuleMember -Function Get-OptimizedGroupMembership
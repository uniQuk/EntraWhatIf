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
                try {
                    $baseUri = "/v1.0/users/$entityId/transitiveMemberOf?`$select=id,displayName,description"
                    $nextLink = $baseUri

                    # Handle pagination to get ALL groups
                    $pageCount = 0
                    do {
                        Write-Verbose "Requesting group membership from Graph API: $nextLink"
                        Write-DiagnosticOutput -Source "Get-OptimizedGroupMembership" -Message "Requesting page $($pageCount+1) of group memberships for $entityType {$entityId}" -Level "Info"
                        $response = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
                        $pageCount++

                        # Enhanced debugging to see the actual API response
                        Write-Verbose "Graph API response received with $(($response.value).Count) groups"
                        Write-DiagnosticOutput -Source "Get-OptimizedGroupMembership" -Message "Page $pageCount returned $(($response.value).Count) groups" -Level "Info"

                        if ($response.value) {
                            $groups += $response.value
                        }

                        # Check if there are more pages
                        $nextLink = $response.'@odata.nextLink'
                        if ($nextLink) {
                            Write-DiagnosticOutput -Source "Get-OptimizedGroupMembership" -Message "Found next page link, continuing pagination" -Level "Info"
                        }
                    } while ($nextLink)

                    Write-Verbose "Total groups retrieved: $($groups.Count)"
                    Write-DiagnosticOutput -Source "Get-OptimizedGroupMembership" -Message "Total groups retrieved for $entityType {$entityId}: $($groups.Count) from $pageCount page(s)" -Level "Info"

                    if ($groups.Count -eq 0) {
                        Write-DiagnosticOutput -Source "Get-OptimizedGroupMembership" -Message "No groups found for $entityType $entityId - verify this is expected" -Level "Warning"
                    }
                    else {
                        Write-Verbose "User is a member of these groups: $($groups.id -join ', ')"
                        $firstFiveGroups = $groups.id | Select-Object -First 5
                        Write-DiagnosticOutput -Source "Get-OptimizedGroupMembership" -Message "First 5 group IDs: $($firstFiveGroups -join ', ')" -Level "Info"
                    }
                }
                catch {
                    # Enhanced error logging and reporting
                    $errorStatus = if ($_.Exception.Response) { $_.Exception.Response.StatusCode } else { "Unknown" }
                    $errorMessage = $_.Exception.Message

                    Write-DiagnosticOutput -Source "Get-OptimizedGroupMembership" -Message "Error retrieving group memberships for user $entityId. Status: $errorStatus, Message: $errorMessage" -Level "Warning"

                    # Special handling for common error cases
                    if ($errorStatus -eq "NotFound") {
                        Write-DiagnosticOutput -Source "Get-OptimizedGroupMembership" -Message "User with ID $entityId not found. Returning empty group list." -Level "Warning"
                    }
                    elseif ($errorMessage -like "*Authorization*" -or $errorMessage -like "*Permission*") {
                        Write-DiagnosticOutput -Source "Get-OptimizedGroupMembership" -Message "Permission issue when accessing user group memberships. Check that you have Directory.Read.All permission." -Level "Warning"
                    }

                    # Always return empty array instead of throwing error
                    $groups = @()
                }
            }
            else {
                # For service principals
                try {
                    $baseUri = "/v1.0/servicePrincipals/$entityId/transitiveMemberOf?`$select=id,displayName,description"
                    $nextLink = $baseUri

                    # Handle pagination to get ALL groups
                    do {
                        $response = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop

                        if ($response.value) {
                            $groups += $response.value
                        }

                        # Check if there are more pages
                        $nextLink = $response.'@odata.nextLink'
                    } while ($nextLink)
                }
                catch {
                    $errorStatus = if ($_.Exception.Response) { $_.Exception.Response.StatusCode } else { "Unknown" }
                    $errorMessage = $_.Exception.Message

                    Write-DiagnosticOutput -Source "Get-OptimizedGroupMembership" -Message "Error retrieving group memberships for service principal $entityId. Status: $errorStatus, Message: $errorMessage" -Level "Warning"

                    # Return empty array for all error cases
                    $groups = @()
                }
            }

            # Update cache
            $script:GroupMembershipCache[$cacheKey] = $groups
            $script:GroupMembershipCacheTime[$cacheKey] = [DateTime]::Now
            Write-DiagnosticOutput -Source "Get-OptimizedGroupMembership" -Message "Updated cache with $($groups.Count) groups for $entityType $entityId" -Level "Info"
        }
        catch {
            $errorMessage = $_.Exception.Message
            Write-DiagnosticOutput -Source "Get-OptimizedGroupMembership" -Message "Failed to retrieve group memberships: $errorMessage" -Level "Error"
            # Return empty array instead of throwing
            return @()
        }
    }

    # Return all groups or filter by specified group IDs
    $memberOf = $script:GroupMembershipCache[$cacheKey]
    Write-DiagnosticOutput -Source "Get-OptimizedGroupMembership" -Message "Retrieved $($memberOf.Count) groups from cache for $entityType $entityId" -Level "Info"

    if ($GroupIds -and $GroupIds.Count -gt 0) {
        $filteredGroups = $memberOf | Where-Object { $_.id -in $GroupIds }
        Write-DiagnosticOutput -Source "Get-OptimizedGroupMembership" -Message "Filtered to $($filteredGroups.Count) out of $($GroupIds.Count) requested groups" -Level "Info"
        return $filteredGroups
    }
    else {
        return $memberOf
    }
}

Export-ModuleMember -Function Get-OptimizedGroupMembership
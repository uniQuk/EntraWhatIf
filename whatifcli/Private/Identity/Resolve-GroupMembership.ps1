function Resolve-GroupMembership {
    <#
    .SYNOPSIS
        Resolves group memberships for users and converts group IDs to readable names.

    .DESCRIPTION
        This function can perform two operations:
        1. Retrieve all groups a user belongs to
        2. Check if a user is a member of specific groups (inclusion/exclusion lists)
        It resolves GUIDs to readable group names for reporting.
        Uses optimized group membership retrieval with caching for better performance.

    .PARAMETER UserId
        The user ID (GUID) to check group membership for

    .PARAMETER ServicePrincipalId
        The service principal ID (GUID) to check group membership for

    .PARAMETER GroupIds
        Optional. Specific group IDs to check membership against (for CA policy inclusion/exclusion lists)

    .PARAMETER IncludeNestedGroups
        Whether to include transitive group memberships (nested groups)

    .PARAMETER ForceRefresh
        Forces a refresh of the group membership cache

    .EXAMPLE
        # Get all groups for a user
        Resolve-GroupMembership -UserId "846eca8a-95ce-4d54-a45c-37b5fea0e3a8"

    .EXAMPLE
        # Check if user is a member of specific groups
        Resolve-GroupMembership -UserId "846eca8a-95ce-4d54-a45c-37b5fea0e3a8" -GroupIds @("groupId1", "groupId2")

    .EXAMPLE
        # Check service principal group membership
        Resolve-GroupMembership -ServicePrincipalId "846eca8a-95ce-4d54-a45c-37b5fea0e3a8" -GroupIds @("groupId1")
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

    try {
        # Ensure either UserId or ServicePrincipalId is provided
        if (-not $UserId -and -not $ServicePrincipalId) {
            throw "Either UserId or ServicePrincipalId must be specified"
        }

        # Initialize results
        $result = [PSCustomObject]@{
            UserId                 = $UserId
            ServicePrincipalId     = $ServicePrincipalId
            Groups                 = @()
            MemberOfSpecificGroups = @{}
            Success                = $false
            Error                  = $null
        }

        # Log diagnostic information
        $entityType = if ($UserId) { "user $UserId" } else { "service principal $ServicePrincipalId" }
        Write-DiagnosticOutput -Source "Resolve-GroupMembership" -Message "Retrieving group memberships for $entityType" -Level "Info"

        # Get group memberships using the optimized function
        $membershipParams = @{
            IncludeNestedGroups = $IncludeNestedGroups
            ForceRefresh        = $ForceRefresh
        }

        if ($UserId) {
            $membershipParams.UserId = $UserId
        }
        else {
            $membershipParams.ServicePrincipalId = $ServicePrincipalId
        }

        # If specific groups are specified, include them in the parameters
        if ($GroupIds -and $GroupIds.Count -gt 0) {
            $membershipParams.GroupIds = $GroupIds
        }

        # Use the optimized function to get memberships
        $groupMemberships = Get-OptimizedGroupMembership @membershipParams

        # Process the results
        if (-not $GroupIds -or $GroupIds.Count -eq 0) {
            # Return all groups the entity belongs to
            foreach ($group in $groupMemberships) {
                $result.Groups += [PSCustomObject]@{
                    Id             = $group.id
                    DisplayName    = $group.displayName
                    Description    = $group.description
                    MembershipType = "Transitive" # Using optimized function always gets transitive memberships
                }
            }
        }
        else {
            # Process specific groups for membership checking
            foreach ($groupId in $GroupIds) {
                $groupMembership = $groupMemberships | Where-Object { $_.id -eq $groupId }
                $isMember = $null -ne $groupMembership

                # Get the group details
                $groupDisplayName = if ($isMember) {
                    $groupMembership.displayName
                }
                else {
                    # Try to get the group name anyway for reporting
                    try {
                        $errorOutput = $null
                        $groupDetails = Get-MgGroup -GroupId $groupId -ErrorAction SilentlyContinue -ErrorVariable errorOutput
                        if ($errorOutput) {
                            Write-DiagnosticOutput -Source "Resolve-GroupMembership" -Message "Group ID $groupId not found or inaccessible (this is normal for non-existent groups)" -Level "Debug"
                            "Unknown Group"
                        }
                        else {
                            $groupDetails.DisplayName
                        }
                    }
                    catch {
                        $errorMessage = $_.Exception.Message
                        Write-DiagnosticOutput -Source "Resolve-GroupMembership" -Message "Error retrieving group details: $errorMessage" -Level "Debug"
                        "Unknown Group"
                    }
                }

                $result.MemberOfSpecificGroups[$groupId] = [PSCustomObject]@{
                    GroupId        = $groupId
                    DisplayName    = $groupDisplayName
                    IsMember       = $isMember
                    MembershipType = if ($isMember) { "Transitive" } else { "None" }
                }
            }
        }

        $result.Success = $true
        return $result
    }
    catch {
        $errorMsg = $_.Exception.Message
        Write-DiagnosticOutput -Source "Resolve-GroupMembership" -Message "Error resolving group membership: $errorMsg" -Level "Error"
        $result.Success = $false
        $result.Error = $errorMsg
        return $result
    }
}
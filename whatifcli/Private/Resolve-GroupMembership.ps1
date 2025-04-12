function Resolve-GroupMembership {
    <#
    .SYNOPSIS
        Resolves group memberships for users and converts group IDs to readable names.

    .DESCRIPTION
        This function can perform two operations:
        1. Retrieve all groups a user belongs to
        2. Check if a user is a member of specific groups (inclusion/exclusion lists)
        It resolves GUIDs to readable group names for reporting.

    .PARAMETER UserId
        The user ID (GUID) to check group membership for

    .PARAMETER GroupIds
        Optional. Specific group IDs to check membership against (for CA policy inclusion/exclusion lists)

    .PARAMETER IncludeNestedGroups
        Whether to include transitive group memberships (nested groups)

    .EXAMPLE
        # Get all groups for a user
        Resolve-GroupMembership -UserId "846eca8a-95ce-4d54-a45c-37b5fea0e3a8"

    .EXAMPLE
        # Check if user is a member of specific groups
        Resolve-GroupMembership -UserId "846eca8a-95ce-4d54-a45c-37b5fea0e3a8" -GroupIds @("groupId1", "groupId2")
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserId,

        [Parameter(Mandatory = $false)]
        [string[]]$GroupIds,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeNestedGroups = $true
    )

    try {
        # Initialize results
        $result = [PSCustomObject]@{
            UserId                 = $UserId
            Groups                 = @()
            MemberOfSpecificGroups = @{}
            Success                = $false
        }

        # Use transitive members if nested groups are requested
        $membershipType = if ($IncludeNestedGroups) { "transitiveMembers" } else { "members" }

        # If no specific groups are specified, get all groups the user belongs to
        if (-not $GroupIds -or $GroupIds.Count -eq 0) {
            # Get all groups the user is a member of
            $memberOfUrl = "/users/{0}/memberOf" -f $UserId
            $userGroups = Invoke-MgGraphRequest -Method GET -Uri $memberOfUrl -ErrorAction Stop

            foreach ($group in $userGroups.value) {
                if ($group.'@odata.type' -eq '#microsoft.graph.group') {
                    $result.Groups += [PSCustomObject]@{
                        Id             = $group.id
                        DisplayName    = $group.displayName
                        Description    = $group.description
                        MembershipType = "Direct"
                    }
                }
            }

            # If we want nested groups, get transitive memberships
            if ($IncludeNestedGroups) {
                $transitiveUrl = "/users/{0}/transitiveMemberOf" -f $UserId
                $transitiveGroups = Invoke-MgGraphRequest -Method GET -Uri $transitiveUrl -ErrorAction Stop

                foreach ($group in $transitiveGroups.value) {
                    if ($group.'@odata.type' -eq '#microsoft.graph.group') {
                        # Only add if not already in the list (to avoid duplicates)
                        if (-not ($result.Groups | Where-Object { $_.Id -eq $group.id })) {
                            $result.Groups += [PSCustomObject]@{
                                Id             = $group.id
                                DisplayName    = $group.displayName
                                Description    = $group.description
                                MembershipType = "Nested"
                            }
                        }
                    }
                }
            }
        }
        else {
            # Check specific groups for membership (for CA policy exclusions/inclusions)
            foreach ($groupId in $GroupIds) {
                try {
                    # Get group details
                    $groupDetails = Get-MgGroup -GroupId $groupId -ErrorAction Stop

                    # Check if user is a member
                    $checkUrl = "/groups/{0}/{1}/{2}/`$ref" -f $groupId, $membershipType, $UserId
                    try {
                        $checkResult = Invoke-MgGraphRequest -Method GET -Uri $checkUrl -ErrorAction Stop
                        $isMember = $true
                    }
                    catch {
                        $isMember = $false
                    }

                    $result.MemberOfSpecificGroups[$groupId] = [PSCustomObject]@{
                        GroupId        = $groupId
                        DisplayName    = $groupDetails.DisplayName
                        IsMember       = $isMember
                        MembershipType = if ($isMember -and $IncludeNestedGroups) { "Direct or Nested" } else { "Direct" }
                    }
                }
                catch {
                    $errorMsg = $_.Exception.Message
                    Write-Verbose ("Could not check group {0}: {1}" -f $groupId, $errorMsg)
                    $result.MemberOfSpecificGroups[$groupId] = [PSCustomObject]@{
                        GroupId     = $groupId
                        DisplayName = "Unknown Group"
                        IsMember    = $false
                        Error       = $errorMsg
                    }
                }
            }
        }

        $result.Success = $true
        return $result
    }
    catch {
        $errorMsg = $_.Exception.Message
        Write-Verbose ("Error resolving group membership: {0}" -f $errorMsg)
        $result.Success = $false
        $result.Error = $errorMsg
        return $result
    }
}
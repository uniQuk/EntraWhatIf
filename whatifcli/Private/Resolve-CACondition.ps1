function Resolve-CACondition {
    <#
    .SYNOPSIS
        Evaluates if a Conditional Access policy's conditions apply to a sign-in scenario.

    .DESCRIPTION
        This function evaluates the conditions of a Conditional Access policy to determine
        if it applies to a given sign-in scenario based on the provided contexts.

    .PARAMETER Policy
        The Conditional Access policy to evaluate.

    .PARAMETER UserContext
        The user context for the sign-in scenario.

    .PARAMETER ResourceContext
        The resource context for the sign-in scenario.

    .PARAMETER DeviceContext
        The device context for the sign-in scenario.

    .PARAMETER RiskContext
        The risk context for the sign-in scenario.

    .PARAMETER LocationContext
        The location context for the sign-in scenario.

    .EXAMPLE
        Resolve-CACondition -Policy $policy -UserContext $UserContext -ResourceContext $ResourceContext -DeviceContext $DeviceContext -RiskContext $RiskContext -LocationContext $LocationContext
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$UserContext,

        [Parameter(Mandatory = $true)]
        [object]$ResourceContext,

        [Parameter(Mandatory = $true)]
        [object]$DeviceContext,

        [Parameter(Mandatory = $true)]
        [object]$RiskContext,

        [Parameter(Mandatory = $true)]
        [object]$LocationContext
    )

    # Initialize evaluation details
    $evaluationDetails = @{
        UserInScope           = $false
        ResourceInScope       = $false
        NetworkInScope        = $false
        ClientAppInScope      = $false
        DevicePlatformInScope = $false
        DeviceStateInScope    = $false
        RiskLevelsInScope     = $false
        Reasons               = @{
            User           = ""
            Resource       = ""
            Network        = ""
            ClientApp      = ""
            DevicePlatform = ""
            DeviceState    = ""
            RiskLevels     = ""
        }
    }

    # 1. Check if user is in scope
    $userScopeResult = Test-UserInScope -Policy $Policy -UserContext $UserContext
    $evaluationDetails.UserInScope = $userScopeResult.InScope
    $evaluationDetails.Reasons.User = $userScopeResult.Reason

    # 2. Check if resource is in scope
    $evaluationDetails.ResourceInScope = Test-ResourceInScope -Policy $Policy -ResourceContext $ResourceContext

    # 3. Check if network location is in scope
    $evaluationDetails.NetworkInScope = Test-NetworkInScope -Policy $Policy -LocationContext $LocationContext

    # 4. Check if client app is in scope
    $evaluationDetails.ClientAppInScope = Test-ClientAppInScope -Policy $Policy -ResourceContext $ResourceContext

    # 5. Check if device platform is in scope
    $evaluationDetails.DevicePlatformInScope = Test-DevicePlatformInScope -Policy $Policy -DeviceContext $DeviceContext

    # 6. Check if device state is in scope
    $evaluationDetails.DeviceStateInScope = Test-DeviceStateInScope -Policy $Policy -DeviceContext $DeviceContext

    # 7. Check if risk levels are in scope
    $evaluationDetails.RiskLevelsInScope = Test-RiskLevelsInScope -Policy $Policy -RiskContext $RiskContext

    # Determine if policy applies (all conditions must be true)
    $applies = (
        $evaluationDetails.UserInScope -and
        $evaluationDetails.ResourceInScope -and
        $evaluationDetails.NetworkInScope -and
        $evaluationDetails.ClientAppInScope -and
        $evaluationDetails.DevicePlatformInScope -and
        $evaluationDetails.DeviceStateInScope -and
        $evaluationDetails.RiskLevelsInScope
    )

    return @{
        Applies           = $applies
        EvaluationDetails = $evaluationDetails
    }
}

function Test-UserInScope {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$UserContext
    )

    # If no user conditions specified, user is in scope
    if (-not $Policy.Conditions.Users) {
        Write-Verbose "No user conditions specified in policy, user is in scope"
        return @{
            InScope = $true
            Reason  = "No user conditions specified"
        }
    }

    $includeUsers = $Policy.Conditions.Users.IncludeUsers
    $excludeUsers = $Policy.Conditions.Users.ExcludeUsers
    $includeGroups = $Policy.Conditions.Users.IncludeGroups
    $excludeGroups = $Policy.Conditions.Users.ExcludeGroups
    $includeRoles = $Policy.Conditions.Users.IncludeRoles
    $excludeRoles = $Policy.Conditions.Users.ExcludeRoles

    # Debug output for troubleshooting
    Write-Verbose "Testing user scope for policy: $($Policy.DisplayName)"
    Write-Verbose "User ID: $($UserContext.Id)"

    # Normalize user ID for comparison - handle both UPN and GUID formats
    $normalizedUserId = $UserContext.Id

    # Check if user is explicitly excluded - CRITICAL CHECK FIRST
    if ($excludeUsers -and $normalizedUserId) {
        Write-Verbose "Checking excluded users: $($excludeUsers -join ', ')"

        # Check for special values
        if ($excludeUsers -contains "GuestsOrExternalUsers" -and $normalizedUserId -like "*#EXT#*") {
            Write-Verbose "User excluded as external user"
            return @{
                InScope = $false
                Reason  = "User excluded as external user"
            }
        }

        foreach ($excludedUser in $excludeUsers) {
            # Case-insensitive comparison
            if ($normalizedUserId -ieq $excludedUser) {
                Write-Verbose "User explicitly excluded by ID: $excludedUser"
                return @{
                    InScope = $false
                    Reason  = "User explicitly excluded"
                }
            }
        }

        # Also check if the user's GUID directly matches any excluded user ID
        if ($UserContext.Id -match "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$") {
            # User ID is already in GUID format
            $userGuid = $UserContext.Id
            Write-Verbose "User ID is already GUID: $userGuid"
        }
        else {
            # We don't have a GUID, but check anyway in case the UPN was resolved
            $userGuid = $UserContext.Id
            Write-Verbose "User ID is not GUID format, using as-is: $userGuid"
        }

        foreach ($excludedUser in $excludeUsers) {
            if ($excludedUser -match "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$" -and
                $userGuid -ieq $excludedUser) {
                Write-Verbose "User explicitly excluded by GUID: $excludedUser"
                return @{
                    InScope = $false
                    Reason  = "User explicitly excluded by GUID"
                }
            }
        }

        # Extra debug check - directly compare to the hard-coded ID we found in the tenant
        if ($userGuid -ieq "846eca8a-95ce-4d54-a45c-37b5fea0e3a8" -or
            $normalizedUserId -ieq "846eca8a-95ce-4d54-a45c-37b5fea0e3a8") {
            Write-Verbose "User explicitly matches known excluded ID from tenant"
            if ($excludeUsers -contains "846eca8a-95ce-4d54-a45c-37b5fea0e3a8") {
                Write-Verbose "Excluded users array contains the ID - confirming exclusion"
                return @{
                    InScope = $false
                    Reason  = "User explicitly excluded by special check"
                }
            }
            else {
                Write-Verbose "ID not in excluded users array despite matching: $($excludeUsers -join ', ')"
            }
        }
    }

    # Check if user is in excluded groups
    if ($excludeGroups -and $UserContext.MemberOf) {
        Write-Verbose "Checking excluded groups: $($excludeGroups -join ', ')"
        Write-Verbose "User's groups: $($UserContext.MemberOf -join ', ')"

        foreach ($group in $UserContext.MemberOf) {
            if ($excludeGroups -contains $group) {
                Write-Verbose "User excluded by group membership: $group"
                return @{
                    InScope = $false
                    Reason  = "User excluded by group membership: $group"
                }
            }
        }
    }

    # Check if user has excluded roles
    if ($excludeRoles -and $UserContext.DirectoryRoles) {
        Write-Verbose "Checking excluded roles: $($excludeRoles -join ', ')"
        Write-Verbose "User's roles: $($UserContext.DirectoryRoles -join ', ')"

        foreach ($role in $UserContext.DirectoryRoles) {
            if ($excludeRoles -contains $role) {
                Write-Verbose "User excluded by role: $role"
                return @{
                    InScope = $false
                    Reason  = "User excluded by role: $role"
                }
            }
        }
    }

    # Check if user is included
    $isIncluded = $false
    $includeReason = ""

    # Check if all users are included
    if ($includeUsers -and $includeUsers -contains "All") {
        Write-Verbose "All users included"
        $isIncluded = $true
        $includeReason = "All users included"
    }
    # Check if user is explicitly included
    elseif ($includeUsers -and $normalizedUserId) {
        Write-Verbose "Checking included users: $($includeUsers -join ', ')"

        # Check for special values
        if ($includeUsers -contains "GuestsOrExternalUsers" -and $normalizedUserId -like "*#EXT#*") {
            Write-Verbose "User included as external user"
            $isIncluded = $true
            $includeReason = "User included as external user"
        }

        foreach ($includedUser in $includeUsers) {
            # Case-insensitive comparison
            if ($normalizedUserId -ieq $includedUser) {
                Write-Verbose "User explicitly included by ID: $includedUser"
                $isIncluded = $true
                $includeReason = "User explicitly included"
                break
            }
        }
    }
    # Check if user is in included groups
    elseif ($includeGroups -and $UserContext.MemberOf) {
        Write-Verbose "Checking included groups: $($includeGroups -join ', ')"
        Write-Verbose "User's groups: $($UserContext.MemberOf -join ', ')"

        foreach ($group in $UserContext.MemberOf) {
            if ($includeGroups -contains $group) {
                Write-Verbose "User included by group membership: $group"
                $isIncluded = $true
                $includeReason = "User included by group membership: $group"
                break
            }
        }
    }
    # Check if user has included roles
    elseif ($includeRoles -and $UserContext.DirectoryRoles) {
        Write-Verbose "Checking included roles: $($includeRoles -join ', ')"
        Write-Verbose "User's roles: $($UserContext.DirectoryRoles -join ', ')"

        foreach ($role in $UserContext.DirectoryRoles) {
            if ($includeRoles -contains $role) {
                Write-Verbose "User included by role: $role"
                $isIncluded = $true
                $includeReason = "User included by role: $role"
                break
            }
        }
    }

    Write-Verbose "Final user in scope determination: $isIncluded"
    return @{
        InScope = $isIncluded
        Reason  = if ($isIncluded) { $includeReason } else { "User not included in policy scope" }
    }
}

function Test-ResourceInScope {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$ResourceContext
    )

    # If no application conditions specified, resource is in scope
    if (-not $Policy.Conditions.Applications) {
        return $true
    }

    $includeApps = $Policy.Conditions.Applications.IncludeApplications
    $excludeApps = $Policy.Conditions.Applications.ExcludeApplications

    # Check if app is explicitly excluded
    if ($excludeApps -and $ResourceContext.AppId -and $ResourceContext.AppId -in $excludeApps) {
        return $false
    }

    # Check if app is included
    $isIncluded = $false

    # Check if all apps are included
    if ($includeApps -and $includeApps -contains "All") {
        $isIncluded = $true
    }
    # Check if app is explicitly included
    elseif ($includeApps -and $ResourceContext.AppId -and $ResourceContext.AppId -in $includeApps) {
        $isIncluded = $true
    }

    return $isIncluded
}

function Test-NetworkInScope {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$LocationContext
    )

    # If no location conditions specified, location is in scope
    if (-not $Policy.Conditions.Locations) {
        return $true
    }

    $includeLocations = $Policy.Conditions.Locations.IncludeLocations
    $excludeLocations = $Policy.Conditions.Locations.ExcludeLocations

    # If no locations specified in the conditions, location is in scope
    if ((-not $includeLocations -or $includeLocations.Count -eq 0) -and
        (-not $excludeLocations -or $excludeLocations.Count -eq 0)) {
        return $true
    }

    # Helper function to check if an IP is in a named location
    function Test-IpInNamedLocation {
        param (
            [string]$IpAddress,
            [string]$LocationId
        )

        # For now, we'll just compare the location name
        # In a real implementation, we'd need to fetch the named location definitions
        # and perform proper IP address matching
        return ($LocationContext.NamedLocation -eq $LocationId)
    }

    # Check if location is explicitly excluded
    if ($excludeLocations) {
        foreach ($location in $excludeLocations) {
            if ($location -eq "All") {
                return $false
            }

            if (Test-IpInNamedLocation -IpAddress $LocationContext.IpAddress -LocationId $location) {
                return $false
            }
        }
    }

    # Check if location is included
    $isIncluded = $false

    # Check if all locations are included
    if ($includeLocations -and $includeLocations -contains "All") {
        $isIncluded = $true
    }
    # Check if location is explicitly included
    elseif ($includeLocations) {
        foreach ($location in $includeLocations) {
            if (Test-IpInNamedLocation -IpAddress $LocationContext.IpAddress -LocationId $location) {
                $isIncluded = $true
                break
            }
        }
    }
    else {
        # If no include locations specified, all locations are included
        $isIncluded = $true
    }

    return $isIncluded
}

function Test-ClientAppInScope {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$ResourceContext
    )

    # If no client app types specified, client app is in scope
    if (-not $Policy.Conditions.ClientAppTypes -or $Policy.Conditions.ClientAppTypes.Count -eq 0) {
        return $true
    }

    # Check if all client apps are included
    if ($Policy.Conditions.ClientAppTypes -contains "all") {
        return $true
    }

    # Check if client app type is explicitly included
    return ($ResourceContext.ClientAppType -in $Policy.Conditions.ClientAppTypes)
}

function Test-DevicePlatformInScope {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$DeviceContext
    )

    # If no platform conditions specified, platform is in scope
    if (-not $Policy.Conditions.Platforms) {
        return $true
    }

    $includePlatforms = $Policy.Conditions.Platforms.IncludePlatforms
    $excludePlatforms = $Policy.Conditions.Platforms.ExcludePlatforms

    # If no platforms specified in the conditions, platform is in scope
    if ((-not $includePlatforms -or $includePlatforms.Count -eq 0) -and
        (-not $excludePlatforms -or $excludePlatforms.Count -eq 0)) {
        return $true
    }

    # Check if platform is explicitly excluded
    if ($excludePlatforms -and $DeviceContext.Platform -and $DeviceContext.Platform -in $excludePlatforms) {
        return $false
    }

    # Check if platform is included
    $isIncluded = $false

    # Check if all platforms are included
    if ($includePlatforms -and $includePlatforms -contains "all") {
        $isIncluded = $true
    }
    # Check if platform is explicitly included
    elseif ($includePlatforms -and $DeviceContext.Platform -and $DeviceContext.Platform -in $includePlatforms) {
        $isIncluded = $true
    }
    else {
        # If no include platforms specified, all platforms are included
        $isIncluded = (-not $includePlatforms -or $includePlatforms.Count -eq 0)
    }

    return $isIncluded
}

function Test-DeviceStateInScope {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$DeviceContext
    )

    # If no device filter specified, device state is in scope
    if (-not $Policy.Conditions.Devices -or -not $Policy.Conditions.Devices.DeviceFilter) {
        return $true
    }

    # Evaluate device filter
    # In a real implementation, this would parse and evaluate the filter rule
    # For now, we'll just check a few common filter scenarios

    $filterRule = $Policy.Conditions.Devices.DeviceFilter.Rule
    $filterMode = $Policy.Conditions.Devices.DeviceFilter.Mode

    # Check for compliance filter
    if ($filterRule -match "device\.isCompliant\s+\-eq\s+True") {
        $isCompliant = $DeviceContext.Compliance

        if ($filterMode -eq "include") {
            return $isCompliant
        }
        elseif ($filterMode -eq "exclude") {
            return -not $isCompliant
        }
    }

    # Check for join type filter
    if ($filterRule -match "device\.trustType\s+\-eq\s+'([^']+)'") {
        $targetJoinType = $matches[1]
        $matchesJoinType = ($DeviceContext.JoinType -eq $targetJoinType)

        if ($filterMode -eq "include") {
            return $matchesJoinType
        }
        elseif ($filterMode -eq "exclude") {
            return -not $matchesJoinType
        }
    }

    # Default to in scope if we can't evaluate the filter
    Write-Warning "Cannot evaluate device filter rule: $filterRule"
    return $true
}

function Test-RiskLevelsInScope {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$RiskContext
    )

    $userRiskLevels = $Policy.Conditions.UserRiskLevels
    $signInRiskLevels = $Policy.Conditions.SignInRiskLevels

    # If no risk levels specified, risk is in scope
    if ((-not $userRiskLevels -or $userRiskLevels.Count -eq 0) -and
        (-not $signInRiskLevels -or $signInRiskLevels.Count -eq 0)) {
        return $true
    }

    $userRiskInScope = $true
    $signInRiskInScope = $true

    # Check user risk level
    if ($userRiskLevels -and $userRiskLevels.Count -gt 0) {
        $userRiskInScope = ($RiskContext.UserRiskLevel -in $userRiskLevels)
    }

    # Check sign-in risk level
    if ($signInRiskLevels -and $signInRiskLevels.Count -gt 0) {
        $signInRiskInScope = ($RiskContext.SignInRiskLevel -in $signInRiskLevels)
    }

    # Both risk levels must be in scope
    return ($userRiskInScope -and $signInRiskInScope)
}
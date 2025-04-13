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
    [OutputType([System.Collections.Hashtable])]
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
    [OutputType([System.Collections.Hashtable])]
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
    Write-Verbose "User ID: $($UserContext.Id), UPN: $($UserContext.UPN)"

    # Normalize user ID and UPN for comparison - handle both UPN and GUID formats
    $normalizedUserId = $UserContext.Id
    $normalizedUserIdLower = if ($UserContext.IdLower) { $UserContext.IdLower } else { $UserContext.Id.ToLower() }
    $normalizedUpn = $UserContext.UPN
    $normalizedUpnLower = if ($UserContext.UpnLower) { $UserContext.UpnLower } else { $UserContext.UPN.ToLower() }

    # Check if user is explicitly excluded - CRITICAL CHECK FIRST
    if ($excludeUsers -and ($normalizedUserId -or $normalizedUpn)) {
        Write-Verbose "Checking excluded users: $($excludeUsers -join ', ')"

        # Check for special values
        if ($excludeUsers -contains "GuestsOrExternalUsers" -and $normalizedUpn -like "*#EXT#*") {
            Write-Verbose "User excluded as external user"
            return @{
                InScope = $false
                Reason  = "User excluded as external user"
            }
        }

        foreach ($excludedUser in $excludeUsers) {
            $excludedUserLower = $excludedUser.ToLower()

            # Case-insensitive comparison for both ID and UPN
            if ($normalizedUserIdLower -eq $excludedUserLower -or $normalizedUpnLower -eq $excludedUserLower) {
                Write-Verbose "User explicitly excluded: $excludedUser (matched as $($normalizedUserIdLower -eq $excludedUserLower ? 'ID' : 'UPN'))"
                return @{
                    InScope = $false
                    Reason  = "User explicitly excluded"
                }
            }
        }
    }

    # Check if user is in excluded groups
    if ($excludeGroups -and $UserContext.MemberOf) {
        Write-Verbose "Checking excluded groups: $($excludeGroups -join ', ')"
        Write-Verbose "User's groups: $($UserContext.MemberOf -join ', ')"

        foreach ($group in $UserContext.MemberOf) {
            $groupLower = $group.ToLower()

            foreach ($excludedGroup in $excludeGroups) {
                if ($groupLower -eq $excludedGroup.ToLower()) {
                    Write-Verbose "User excluded by group membership: $group"
                    return @{
                        InScope = $false
                        Reason  = "User excluded by group membership: $group"
                    }
                }
            }
        }
    }

    # Check if user has excluded roles
    if ($excludeRoles -and $UserContext.DirectoryRoles) {
        Write-Verbose "Checking excluded roles: $($excludeRoles -join ', ')"
        Write-Verbose "User's roles: $($UserContext.DirectoryRoles -join ', ')"

        foreach ($role in $UserContext.DirectoryRoles) {
            $roleLower = $role.ToLower()

            foreach ($excludedRole in $excludeRoles) {
                if ($roleLower -eq $excludedRole.ToLower()) {
                    Write-Verbose "User excluded by role: $role"
                    return @{
                        InScope = $false
                        Reason  = "User excluded by role: $role"
                    }
                }
            }
        }
    }

    # Check if user is included
    $isIncluded = $false
    $includeReason = ""

    # Check if all users are included (handle both 'All' and 'all' case variations)
    if ($includeUsers -and ($includeUsers -contains "All" -or $includeUsers -contains "all")) {
        Write-Verbose "All users included in policy"
        $isIncluded = $true
        $includeReason = "All users included"
    }
    # Check if user is explicitly included
    elseif ($includeUsers -and ($normalizedUserId -or $normalizedUpn)) {
        Write-Verbose "Checking included users: $($includeUsers -join ', ')"

        # Check for special values
        if ($includeUsers -contains "GuestsOrExternalUsers" -and $normalizedUpn -like "*#EXT#*") {
            Write-Verbose "User included as external user"
            $isIncluded = $true
            $includeReason = "User included as external user"
        }

        foreach ($includedUser in $includeUsers) {
            $includedUserLower = $includedUser.ToLower()

            # Case-insensitive comparison for both ID and UPN
            if ($normalizedUserIdLower -eq $includedUserLower -or $normalizedUpnLower -eq $includedUserLower) {
                Write-Verbose "User explicitly included: $includedUser (matched as $($normalizedUserIdLower -eq $includedUserLower ? 'ID' : 'UPN'))"
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
            $groupLower = $group.ToLower()

            foreach ($includedGroup in $includeGroups) {
                if ($groupLower -eq $includedGroup.ToLower()) {
                    Write-Verbose "User included by group membership: $group"
                    $isIncluded = $true
                    $includeReason = "User included by group membership: $group"
                    break 2  # Break out of both loops
                }
            }
        }
    }
    # Check if user has included roles
    elseif ($includeRoles -and $UserContext.DirectoryRoles) {
        Write-Verbose "Checking included roles: $($includeRoles -join ', ')"
        Write-Verbose "User's roles: $($UserContext.DirectoryRoles -join ', ')"

        foreach ($role in $UserContext.DirectoryRoles) {
            $roleLower = $role.ToLower()

            foreach ($includedRole in $includeRoles) {
                if ($roleLower -eq $includedRole.ToLower()) {
                    Write-Verbose "User included by role: $role"
                    $isIncluded = $true
                    $includeReason = "User included by role: $role"
                    break 2  # Break out of both loops
                }
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
    [OutputType([System.Boolean])]
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

    Write-Verbose "Testing resource scope for policy: $($Policy.DisplayName)"
    Write-Verbose "App ID: $($ResourceContext.AppId), DisplayName: $($ResourceContext.DisplayName)"

    # Check if app is explicitly excluded
    if ($excludeApps -and $ResourceContext.AppId) {
        foreach ($excludedApp in $excludeApps) {
            if ($ResourceContext.AppId -ieq $excludedApp) {
                Write-Verbose "App explicitly excluded: $excludedApp"
                return $false
            }
        }
    }

    # Check if app is included
    $isIncluded = $false

    # Check if all apps are included (handle both 'All' and 'all' case variations)
    if ($includeApps) {
        foreach ($includeApp in $includeApps) {
            if ($includeApp -ieq "All") {
                Write-Verbose "All applications included in policy"
                $isIncluded = $true
                break
            }
        }
    }

    # Check if app is explicitly included
    if (-not $isIncluded -and $includeApps -and $ResourceContext.AppId) {
        foreach ($includedApp in $includeApps) {
            if ($ResourceContext.AppId -ieq $includedApp) {
                Write-Verbose "App explicitly included: $includedApp"
                $isIncluded = $true
                break
            }
        }
    }

    return $isIncluded
}

function Test-NetworkInScope {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
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
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string]$IpAddress,

            [Parameter(Mandatory = $true)]
            [string]$LocationId
        )

        Write-Verbose "Testing if IP '$IpAddress' is in named location with ID '$LocationId'"

        # Check if we have the named location in our context
        if (-not $LocationContext.NamedLocations -or $LocationContext.NamedLocations.Count -eq 0) {
            Write-Verbose "No named locations available in context"
            return $false
        }

        # Find the named location
        $namedLocation = $LocationContext.NamedLocations | Where-Object { $_.Id -eq $LocationId }
        if (-not $namedLocation) {
            Write-Verbose "Named location with ID '$LocationId' not found"
            return $false
        }

        Write-Verbose "Found named location: $($namedLocation.DisplayName)"

        # Check if it's an IP-based location
        if ($namedLocation.'@odata.type' -eq "#microsoft.graph.ipNamedLocation") {
            Write-Verbose "Location is an IP-based location"

            # Try to parse the input IP address
            try {
                $ipObj = [System.Net.IPAddress]::Parse($IpAddress)
                Write-Verbose "IP address is valid"
            }
            catch {
                Write-Verbose "Invalid IP address format: $IpAddress"
                return $false
            }

            # Check if the IP is in any of the CIDR ranges
            foreach ($range in $namedLocation.IpRanges) {
                if ($range.'@odata.type' -eq "#microsoft.graph.iPv4CidrRange") {
                    $cidrAddress = $range.cidrAddress
                    Write-Verbose "Testing CIDR range: $cidrAddress"

                    # Split CIDR notation into IP and prefix
                    $parts = $cidrAddress.Split('/')
                    if ($parts.Length -ne 2) {
                        Write-Verbose "Invalid CIDR format: $cidrAddress"
                        continue
                    }

                    $networkAddress = $parts[0]
                    $prefixLength = [int]$parts[1]

                    # Convert IP addresses to integers for comparison
                    $ipInt = ConvertTo-IPv4Int $IpAddress
                    $networkInt = ConvertTo-IPv4Int $networkAddress

                    # Calculate the bitmask for the prefix length
                    $mask = ([System.Math]::Pow(2, 32) - 1) -shl (32 - $prefixLength)

                    # Check if the IP is in the network
                    $ipNetwork = $ipInt -band $mask
                    $isInRange = $ipNetwork -eq ($networkInt -band $mask)

                    Write-Verbose "IP in range: $isInRange"
                    if ($isInRange) {
                        return $true
                    }
                }
                else {
                    Write-Verbose "Skipping non-IPv4 range: $($range.'@odata.type')"
                }
            }

            Write-Verbose "IP $IpAddress is not in any CIDR range of the named location"
            return $false
        }
        elseif ($namedLocation.'@odata.type' -eq "#microsoft.graph.countryNamedLocation") {
            # For country-based locations, we'll rely on the country code in the LocationContext
            Write-Verbose "Location is a country-based location"

            if (-not $LocationContext.CountryCode) {
                Write-Verbose "No country code specified in the context"
                return $false
            }

            $isInCountryList = $namedLocation.CountriesAndRegions -contains $LocationContext.CountryCode
            $includeUnknown = $namedLocation.IncludeUnknownCountriesAndRegions

            Write-Verbose "Country '$($LocationContext.CountryCode)' in list: $isInCountryList"
            Write-Verbose "Include unknown countries: $includeUnknown"

            return $isInCountryList -or ($includeUnknown -and -not $LocationContext.CountryCode)
        }

        Write-Verbose "Location type is not supported: $($namedLocation.'@odata.type')"
        return $false
    }

    # Helper function to convert an IPv4 address to an integer
    function ConvertTo-IPv4Int {
        param (
            [string]$IpAddress
        )

        $bytes = [System.Net.IPAddress]::Parse($IpAddress).GetAddressBytes()
        # Reverse for network byte order
        [Array]::Reverse($bytes)
        return [BitConverter]::ToUInt32($bytes, 0)
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
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$ResourceContext
    )

    # If no client app types specified, client app is in scope
    if (-not $Policy.Conditions.ClientAppTypes -or $Policy.Conditions.ClientAppTypes.Count -eq 0) {
        Write-Verbose "No client app types specified in policy, all client apps in scope"
        return $true
    }

    Write-Verbose "Testing client app scope for policy: $($Policy.DisplayName)"
    Write-Verbose "Client app type: $($ResourceContext.ClientAppType)"

    # Check if all client apps are included (case-insensitive check for "all" or "All")
    foreach ($clientAppType in $Policy.Conditions.ClientAppTypes) {
        if ($clientAppType -ieq "all") {
            Write-Verbose "All client app types included in policy"
            return $true
        }
    }

    # Check if client app type is explicitly included (case-insensitive)
    foreach ($clientAppType in $Policy.Conditions.ClientAppTypes) {
        if ($ResourceContext.ClientAppType -ieq $clientAppType) {
            Write-Verbose "Client app type explicitly included: $clientAppType"
            return $true
        }
    }

    Write-Verbose "Client app type not in scope: $($ResourceContext.ClientAppType)"
    return $false
}

function Test-DevicePlatformInScope {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$DeviceContext
    )

    # If no device platform conditions specified, platform is in scope
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
    if ($includePlatforms -and $includePlatforms -contains "All") {
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
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$DeviceContext
    )

    # If no device state conditions specified, device state is in scope
    if (-not $Policy.Conditions.Devices) {
        return $true
    }

    # Simplified for now - just check device compliance state and join type
    # In a real implementation, we'd need to evaluate device filter rules
    # and other device state conditions

    # For this WhatIf implementation, we'll support compliance and join type
    return $true
}

function Test-DeviceFilter {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Device,

        [Parameter(Mandatory = $true)]
        [string]$FilterRule
    )

    # Parse the filter rule
    # Format: (device.joinType -eq "AzureAD") or (device.compliant -eq true)
    # For now, just handle simple cases

    # Extract the property name, operator, and value
    if ($FilterRule -match '([a-zA-Z.]+)\s+(-eq|-ne)\s+(".*?"|true|false)') {
        $propertyPath = $matches[1]
        $operator = $matches[2]
        $valueString = $matches[3] -replace '"'

        # Convert string to boolean if needed
        if ($valueString -eq 'true') {
            $value = $true
        }
        elseif ($valueString -eq 'false') {
            $value = $false
        }
        else {
            $value = $valueString
        }

        # Get the property from the device object
        $actualValue = $null
        switch ($propertyPath) {
            "device.joinType" { $actualValue = $Device.JoinType }
            "device.compliant" { $actualValue = $Device.Compliance }
            "device.ApprovedApplication" { $actualValue = $Device.ApprovedApplication }
            "device.AppProtectionPolicy" { $actualValue = $Device.AppProtectionPolicy }
            default { $actualValue = $null }
        }

        # Evaluate the condition
        $filterMatches = $false
        switch ($operator) {
            "-eq" { $filterMatches = ($actualValue -eq $value) }
            "-ne" { $filterMatches = ($actualValue -ne $value) }
            default { $filterMatches = $false }
        }

        return $filterMatches
    }

    # Handle include/exclude filter mode for joinType
    # Format: device.joinType -in ["Azure AD joined", "Azure AD registered"]
    elseif ($FilterRule -match '([a-zA-Z.]+)\s+(-in|-notin)\s+\[(.*?)\]') {
        $propertyPath = $matches[1]
        $operator = $matches[2]
        $valuesString = $matches[3]

        # Parse the values - split by comma and remove quotes
        $values = $valuesString -split ',' | ForEach-Object { $_.Trim().Trim('"') }

        # Get the property from the device object
        $actualValue = $null
        switch ($propertyPath) {
            "device.joinType" {
                # Convert friendly names to internal values
                $joinTypeMap = @{
                    "Azure AD joined"        = "AzureAD"
                    "Hybrid Azure AD joined" = "Hybrid"
                    "Azure AD registered"    = "Registered"
                    "Registered"             = "Registered"
                }

                # Check if the device join type matches any of the values
                $filterMatches = $false
                foreach ($value in $values) {
                    $mappedValue = $joinTypeMap[$value]
                    if ($mappedValue -and $Device.JoinType -eq $mappedValue) {
                        $filterMatches = $true
                        break
                    }
                }
            }
            default {
                $filterMatches = $false
            }
        }

        # Determine include/exclude mode
        $filterMode = if ($operator -eq "-in") { "include" } else { "exclude" }

        if ($filterMode -eq "include") {
            return $filterMatches
        }
        elseif ($filterMode -eq "exclude") {
            return -not $filterMatches
        }
    }

    # Default to in scope if we can't evaluate the filter
    Write-Warning "Cannot evaluate device filter rule: $filterRule"
    return $true
}

function Test-RiskLevelsInScope {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$RiskContext
    )

    # If no risk levels specified, all risk levels are in scope
    $userRiskInScope = (-not $Policy.Conditions.UserRiskLevels -or
        $Policy.Conditions.UserRiskLevels.Count -eq 0 -or
        $RiskContext.UserRiskLevel -in $Policy.Conditions.UserRiskLevels)

    $signInRiskInScope = (-not $Policy.Conditions.SignInRiskLevels -or
        $Policy.Conditions.SignInRiskLevels.Count -eq 0 -or
        $RiskContext.SignInRiskLevel -in $Policy.Conditions.SignInRiskLevels)

    return ($userRiskInScope -and $signInRiskInScope)
}


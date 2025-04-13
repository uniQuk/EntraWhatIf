function Resolve-CACondition {
    <#
    .SYNOPSIS
        Evaluates if a Conditional Access policy's conditions apply to a sign-in scenario.

    .DESCRIPTION
        This function evaluates the conditions of a Conditional Access policy to determine
        if it applies to a given sign-in scenario based on the provided contexts.

        The evaluation follows Microsoft's implementation order with early exits:
        1. First check policy state
        2. Check user exclusions with early exit
        3. Check user inclusions with early exit
        4. Check application/resource exclusions with early exit
        5. Check application/resource inclusions with early exit
        6. Check remaining conditions in order

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

    # Initialize evaluation details with reasons tracking
    $evaluationDetails = @{
        PolicyStateInScope           = $false
        UserExcluded                 = $false
        UserIncluded                 = $false
        ResourceExcluded             = $false
        ResourceIncluded             = $false
        ResourceInScope              = $false
        NetworkInScope               = $false
        ClientAppInScope             = $false
        DevicePlatformInScope        = $false
        DeviceStateInScope           = $false
        UserRiskLevelInScope         = $false
        SignInRiskLevelInScope       = $false
        AuthenticationContextInScope = $false
        Reasons                      = @{
            PolicyState           = ""
            User                  = ""
            Resource              = ""
            Network               = ""
            ClientApp             = ""
            DevicePlatform        = ""
            DeviceState           = ""
            UserRiskLevel         = ""
            SignInRiskLevel       = ""
            AuthenticationContext = ""
        }
    }

    # 1. Check policy state first
    if ($Policy.State -ne "enabled" -and $Policy.State -ne "enabledForReportingButNotEnforced") {
        $evaluationDetails.Reasons.PolicyState = "Policy not enabled"
        Write-Verbose "Policy $($Policy.DisplayName) is not enabled. State: $($Policy.State)"
        return @{
            Applies           = $false
            EvaluationDetails = $evaluationDetails
            Reason            = "Policy not enabled"
        }
    }

    $evaluationDetails.PolicyStateInScope = $true
    $evaluationDetails.Reasons.PolicyState = "Policy is enabled"

    # 2. Check user exclusions first (critical early exit)
    $userExclusionResult = Test-UserExclusions -Policy $Policy -UserContext $UserContext
    $evaluationDetails.UserExcluded = $userExclusionResult.Excluded
    $evaluationDetails.Reasons.User = $userExclusionResult.Reason

    if ($userExclusionResult.Excluded) {
        Write-Verbose "User excluded from policy $($Policy.DisplayName): $($userExclusionResult.Reason)"
        return @{
            Applies           = $false
            EvaluationDetails = $evaluationDetails
            Reason            = $userExclusionResult.Reason
        }
    }

    # 3. Then check user inclusions
    $userInclusionResult = Test-UserInclusions -Policy $Policy -UserContext $UserContext
    $evaluationDetails.UserIncluded = $userInclusionResult.Included
    $evaluationDetails.Reasons.User = $userInclusionResult.Reason

    if (-not $userInclusionResult.Included) {
        Write-Verbose "User not included in policy $($Policy.DisplayName): $($userInclusionResult.Reason)"
        return @{
            Applies           = $false
            EvaluationDetails = $evaluationDetails
            Reason            = $userInclusionResult.Reason
        }
    }

    # Store that the user is in scope (is included and not excluded)
    $evaluationDetails.UserInScope = $true

    # 4. Check application/resource exclusions with early exit
    $resourceExclusionResult = Test-ResourceExclusions -Policy $Policy -ResourceContext $ResourceContext
    $evaluationDetails.ResourceExcluded = $resourceExclusionResult.Excluded
    $evaluationDetails.Reasons.Resource = $resourceExclusionResult.Reason

    if ($resourceExclusionResult.Excluded) {
        Write-Verbose "Resource excluded from policy $($Policy.DisplayName): $($resourceExclusionResult.Reason)"
        return @{
            Applies           = $false
            EvaluationDetails = $evaluationDetails
            Reason            = $resourceExclusionResult.Reason
        }
    }

    # 5. Check application/resource inclusions with early exit
    $resourceInclusionResult = Test-ResourceInclusions -Policy $Policy -ResourceContext $ResourceContext
    $evaluationDetails.ResourceIncluded = $resourceInclusionResult.Included

    if (-not $resourceInclusionResult.Included) {
        $evaluationDetails.Reasons.Resource = $resourceInclusionResult.Reason
        Write-Verbose "Resource not included in policy $($Policy.DisplayName): $($resourceInclusionResult.Reason)"
        return @{
            Applies           = $false
            EvaluationDetails = $evaluationDetails
            Reason            = $resourceInclusionResult.Reason
        }
    }

    $evaluationDetails.Reasons.Resource = $resourceInclusionResult.Reason
    $evaluationDetails.ResourceInScope = $true

    # 5.5 Check authentication context if applicable
    if ($ResourceContext.AuthenticationContext) {
        $authContextResult = Test-AuthenticationContextInScope -Policy $Policy -AuthenticationContext $ResourceContext.AuthenticationContext
        $evaluationDetails.AuthenticationContextInScope = $authContextResult.InScope
        $evaluationDetails.Reasons.AuthenticationContext = $authContextResult.Reason

        if (-not $authContextResult.InScope) {
            Write-Verbose "Authentication context not in scope for policy $($Policy.DisplayName): $($authContextResult.Reason)"
            return @{
                Applies           = $false
                EvaluationDetails = $evaluationDetails
                Reason            = $authContextResult.Reason
            }
        }
    }

    # 6. Check if network location is in scope
    $networkResult = Test-NetworkInScope -Policy $Policy -LocationContext $LocationContext
    $evaluationDetails.NetworkInScope = $networkResult.InScope
    $evaluationDetails.Reasons.Network = $networkResult.Reason

    if (-not $networkResult.InScope) {
        Write-Verbose "Network not in scope for policy $($Policy.DisplayName): $($networkResult.Reason)"
        return @{
            Applies           = $false
            EvaluationDetails = $evaluationDetails
            Reason            = $networkResult.Reason
        }
    }

    # 7. Check if client app is in scope
    $clientAppResult = Test-ClientAppInScope -Policy $Policy -ResourceContext $ResourceContext
    $evaluationDetails.ClientAppInScope = $clientAppResult.InScope
    $evaluationDetails.Reasons.ClientApp = $clientAppResult.Reason

    if (-not $clientAppResult.InScope) {
        Write-Verbose "Client app not in scope for policy $($Policy.DisplayName): $($clientAppResult.Reason)"
        return @{
            Applies           = $false
            EvaluationDetails = $evaluationDetails
            Reason            = $clientAppResult.Reason
        }
    }

    # 8. Check if device platform is in scope
    $devicePlatformResult = Test-DevicePlatformInScope -Policy $Policy -DeviceContext $DeviceContext
    $evaluationDetails.DevicePlatformInScope = $devicePlatformResult.InScope
    $evaluationDetails.Reasons.DevicePlatform = $devicePlatformResult.Reason

    if (-not $devicePlatformResult.InScope) {
        Write-Verbose "Device platform not in scope for policy $($Policy.DisplayName): $($devicePlatformResult.Reason)"
        return @{
            Applies           = $false
            EvaluationDetails = $evaluationDetails
            Reason            = $devicePlatformResult.Reason
        }
    }

    # 9. Check if device state is in scope
    Write-Verbose "Evaluating device state condition..."
    # Add a dump of the devices condition structure for debugging
    if ($null -eq $Policy.Conditions.Devices) {
        Write-Verbose "DEBUG: Policy.Conditions.Devices is null"
    }
    else {
        Write-Verbose "DEBUG: Policy.Conditions.Devices type: $($Policy.Conditions.Devices.GetType().FullName)"
        Write-Verbose "DEBUG: Policy.Conditions.Devices value: $(ConvertTo-Json -InputObject $Policy.Conditions.Devices -Depth 3 -Compress)"
    }

    $deviceStateResult = Test-DeviceStateInScope -Policy $Policy -DeviceContext $DeviceContext
    $evaluationDetails.DeviceStateInScope = $deviceStateResult.InScope
    $evaluationDetails.Reasons.DeviceState = $deviceStateResult.Reason

    Write-Verbose "Device state evaluation result: $($deviceStateResult.InScope), Reason: $($deviceStateResult.Reason)"

    if (-not $deviceStateResult.InScope) {
        Write-Verbose "Device state not in scope for policy $($Policy.DisplayName): $($deviceStateResult.Reason)"
        return @{
            Applies           = $false
            EvaluationDetails = $evaluationDetails
            Reason            = $deviceStateResult.Reason
        }
    }

    # 10. Check if user risk level is in scope
    $userRiskResult = Test-UserRiskLevelInScope -Policy $Policy -RiskContext $RiskContext
    $evaluationDetails.UserRiskLevelInScope = $userRiskResult.InScope
    $evaluationDetails.Reasons.UserRiskLevel = $userRiskResult.Reason

    if (-not $userRiskResult.InScope) {
        Write-Verbose "User risk level not in scope for policy $($Policy.DisplayName): $($userRiskResult.Reason)"
        return @{
            Applies           = $false
            EvaluationDetails = $evaluationDetails
            Reason            = $userRiskResult.Reason
        }
    }

    # 11. Check if sign-in risk level is in scope
    $signInRiskResult = Test-SignInRiskLevelInScope -Policy $Policy -RiskContext $RiskContext
    $evaluationDetails.SignInRiskLevelInScope = $signInRiskResult.InScope
    $evaluationDetails.Reasons.SignInRiskLevel = $signInRiskResult.Reason

    if (-not $signInRiskResult.InScope) {
        Write-Verbose "Sign-in risk level not in scope for policy $($Policy.DisplayName): $($signInRiskResult.Reason)"
        return @{
            Applies           = $false
            EvaluationDetails = $evaluationDetails
            Reason            = $signInRiskResult.Reason
        }
    }

    # If we've reached this point, all conditions are satisfied
    return @{
        Applies           = $true
        EvaluationDetails = $evaluationDetails
        Reason            = "All conditions satisfied"
    }
}

function Test-UserExclusions {
    <#
    .SYNOPSIS
        Tests if a user is excluded from a Conditional Access policy.

    .DESCRIPTION
        This function checks if a user is excluded from a Conditional Access policy
        based on various exclusion criteria like direct user exclusion, group exclusion, etc.

    .PARAMETER Policy
        The Conditional Access policy to evaluate.

    .PARAMETER UserContext
        The user context for the sign-in scenario.

    .EXAMPLE
        Test-UserExclusions -Policy $policy -UserContext $UserContext
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$UserContext
    )

    $result = @{
        Excluded = $false
        Reason   = ""
    }

    # Determine if we're dealing with a user or service principal
    $isServicePrincipal = $UserContext.IsServicePrincipal -eq $true

    if ($isServicePrincipal) {
        # Check if the service principal is excluded
        if ($Policy.Conditions.Users.ExcludeServicePrincipals -and
            ($Policy.Conditions.Users.ExcludeServicePrincipals -contains $UserContext.Id -or
            $Policy.Conditions.Users.ExcludeServicePrincipals -contains $UserContext.AppId)) {
            $result.Excluded = $true
            $result.Reason = "Service principal explicitly excluded"
            return $result
        }

        # No further exclusion checks for service principals
        return $result
    }

    # The rest is for regular users

    # Check if user is directly excluded
    if ($Policy.Conditions.Users.ExcludeUsers -and $Policy.Conditions.Users.ExcludeUsers -contains $UserContext.Id) {
        $result.Excluded = $true
        $result.Reason = "User explicitly excluded"
        return $result
    }

    # Check if user is in an excluded group
    if ($Policy.Conditions.Users.ExcludeGroups -and $Policy.Conditions.Users.ExcludeGroups.Count -gt 0) {
        # Check if user is a member of any excluded group
        foreach ($groupId in $Policy.Conditions.Users.ExcludeGroups) {
            if ($UserContext.MemberOf -contains $groupId) {
                $result.Excluded = $true
                $result.Reason = "User is a member of excluded group $groupId"
                return $result
            }
        }
    }

    # Check if user is in an excluded role
    if ($Policy.Conditions.Users.ExcludeRoles -and $Policy.Conditions.Users.ExcludeRoles.Count -gt 0) {
        # Check if user is a member of any excluded role
        foreach ($roleId in $Policy.Conditions.Users.ExcludeRoles) {
            if ($UserContext.DirectoryRoles -contains $roleId) {
                $result.Excluded = $true
                $result.Reason = "User has excluded role $roleId"
                return $result
            }
        }
    }

    # Check for guest or external user exclusion
    if (Test-SpecialValue -Collection $Policy.Conditions.Users.ExcludeUsers -ValueType "GuestsOrExternalUsers") {
        # Check if user is a guest (implementation depends on how you determine guest status)
        $isGuest = $UserContext.UserType -eq "Guest" -or $UserContext.UPN -match "#EXT#"

        if ($isGuest) {
            $result.Excluded = $true
            $result.Reason = "User is excluded as guest or external user"
            return $result
        }
    }

    return $result
}

function Test-UserInclusions {
    <#
    .SYNOPSIS
        Tests if a user is included in a Conditional Access policy.

    .DESCRIPTION
        This function checks if a user is included in a Conditional Access policy
        based on various inclusion criteria like direct user inclusion, group inclusion, etc.

    .PARAMETER Policy
        The Conditional Access policy to evaluate.

    .PARAMETER UserContext
        The user context for the sign-in scenario.

    .EXAMPLE
        Test-UserInclusions -Policy $policy -UserContext $UserContext
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$UserContext
    )

    $result = @{
        Included = $false
        Reason   = ""
    }

    # Determine if we're dealing with a user or service principal
    $isServicePrincipal = $UserContext.IsServicePrincipal -eq $true

    if ($isServicePrincipal) {
        # Use the specialized function for service principals
        $spResult = Test-ServicePrincipalInScope -Policy $Policy -ServicePrincipalContext $UserContext
        $result.Included = $spResult.InScope
        $result.Reason = $spResult.Reason
        return $result
    }

    # If AllUsers special value is present, all users are included
    if (Test-SpecialValue -Collection $Policy.Conditions.Users.IncludeUsers -ValueType "AllUsers") {
        $result.Included = $true
        $result.Reason = "All users are included"
        return $result
    }

    # Check if user is directly included
    if ($Policy.Conditions.Users.IncludeUsers -and $Policy.Conditions.Users.IncludeUsers -contains $UserContext.Id) {
        $result.Included = $true
        $result.Reason = "User explicitly included"
        return $result
    }

    # Check if user is in an included group
    if ($Policy.Conditions.Users.IncludeGroups -and $Policy.Conditions.Users.IncludeGroups.Count -gt 0) {
        # Check if user is a member of any included group
        foreach ($groupId in $Policy.Conditions.Users.IncludeGroups) {
            if ($UserContext.MemberOf -contains $groupId) {
                $result.Included = $true
                $result.Reason = "User is a member of included group $groupId"
                return $result
            }
        }
    }

    # Check if user is in an included role
    if ($Policy.Conditions.Users.IncludeRoles -and $Policy.Conditions.Users.IncludeRoles.Count -gt 0) {
        # Check if user is a member of any included role
        foreach ($roleId in $Policy.Conditions.Users.IncludeRoles) {
            if ($UserContext.DirectoryRoles -contains $roleId) {
                $result.Included = $true
                $result.Reason = "User has included role $roleId"
                return $result
            }
        }
    }

    # Check for guest or external user inclusion
    if (Test-SpecialValue -Collection $Policy.Conditions.Users.IncludeUsers -ValueType "GuestsOrExternalUsers") {
        # Check if user is a guest (implementation depends on how you determine guest status)
        $isGuest = $UserContext.UserType -eq "Guest" -or $UserContext.UPN -match "#EXT#"

        if ($isGuest) {
            $result.Included = $true
            $result.Reason = "User is included as guest or external user"
            return $result
        }
    }

    # If we got this far, check if there's any inclusion criteria at all
    if (($Policy.Conditions.Users.IncludeUsers -and $Policy.Conditions.Users.IncludeUsers.Count -gt 0) -or
        ($Policy.Conditions.Users.IncludeGroups -and $Policy.Conditions.Users.IncludeGroups.Count -gt 0) -or
        ($Policy.Conditions.Users.IncludeRoles -and $Policy.Conditions.Users.IncludeRoles.Count -gt 0)) {
        # There are inclusion criteria, but this user doesn't match any
        $result.Reason = "User does not match any inclusion criteria"
    }
    else {
        # No inclusion criteria specified, so all users are included by default
        $result.Included = $true
        $result.Reason = "No inclusion criteria specified, all users included by default"
    }

    return $result
}

function Test-ResourceExclusions {
    <#
    .SYNOPSIS
        Tests if a resource or user action is excluded from a Conditional Access policy.

    .DESCRIPTION
        This function checks if a resource (application) or user action is excluded from
        a Conditional Access policy. It enforces mutual exclusivity between applications
        and user actions - a context can't be both an application and a user action.

    .PARAMETER Policy
        The Conditional Access policy to evaluate.

    .PARAMETER ResourceContext
        The resource context for the sign-in scenario, containing application and/or user action information.

    .EXAMPLE
        Test-ResourceExclusions -Policy $policy -ResourceContext $ResourceContext
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$ResourceContext
    )

    # If no application conditions specified, resource is not excluded
    if (-not $Policy.Conditions.Applications) {
        Write-Verbose "No application conditions specified in policy, resource is not excluded"
        return @{
            Excluded = $false
            Reason   = "No application conditions specified"
        }
    }

    $excludeApplications = $Policy.Conditions.Applications.ExcludeApplications
    $excludeUserActions = $Policy.Conditions.Applications.ExcludeUserActions
    $excludeAuthContexts = $Policy.Conditions.Applications.ExcludeAuthenticationContextClassReferences

    # Detect what type of context we're evaluating (application or user action)
    # Check for mutual exclusivity - a context can't be both an application and a user action
    $isUserAction = [bool]$ResourceContext.UserAction
    $isApplication = [bool]$ResourceContext.AppId -and -not $isUserAction

    # If this is a user action context but the policy only excludes applications, not excluded
    if ($isUserAction -and $excludeApplications -and -not $excludeUserActions) {
        Write-Verbose "Resource is a user action, but policy only excludes applications"
        return @{
            Excluded = $false
            Reason   = "Policy excludes applications, not user actions"
        }
    }

    # If this is an application context but the policy only excludes user actions, not excluded
    if ($isApplication -and $excludeUserActions -and -not $excludeApplications) {
        Write-Verbose "Resource is an application, but policy only excludes user actions"
        return @{
            Excluded = $false
            Reason   = "Policy excludes user actions, not applications"
        }
    }

    # Check for UserAction exclusions if this is a user action context
    if ($isUserAction -and $excludeUserActions) {
        Write-Verbose "Checking excluded user actions: $($excludeUserActions -join ', ')"

        if ($excludeUserActions -contains $ResourceContext.UserAction) {
            Write-Verbose "User action explicitly excluded: $($ResourceContext.UserAction)"
            return @{
                Excluded = $true
                Reason   = "User action explicitly excluded"
            }
        }

        # User action is not excluded
        return @{
            Excluded = $false
            Reason   = "User action not excluded"
        }
    }

    # Check if app is excluded (only if this is an application context)
    if ($isApplication -and $excludeApplications) {
        Write-Verbose "Checking excluded applications: $($excludeApplications -join ', ')"

        # Case-insensitive comparison
        $appId = $ResourceContext.AppId.ToLower()

        foreach ($excludedApp in $excludeApplications) {
            if ($appId -eq $excludedApp.ToLower()) {
                Write-Verbose "Application explicitly excluded: $excludedApp"
                return @{
                    Excluded = $true
                    Reason   = "Application explicitly excluded"
                }
            }
        }

        # Application is not excluded
        return @{
            Excluded = $false
            Reason   = "Application not excluded"
        }
    }

    # Check for Authentication Context exclusions if present
    if ($excludeAuthContexts -and $ResourceContext.AuthenticationContext) {
        Write-Verbose "Checking excluded authentication contexts: $($excludeAuthContexts -join ', ')"

        if ($excludeAuthContexts -contains $ResourceContext.AuthenticationContext) {
            Write-Verbose "Authentication context explicitly excluded: $($ResourceContext.AuthenticationContext)"
            return @{
                Excluded = $true
                Reason   = "Authentication context explicitly excluded"
            }
        }
    }

    # Resource is not excluded
    return @{
        Excluded = $false
        Reason   = "Resource not in any exclusion lists"
    }
}

function Test-ResourceInclusions {
    <#
    .SYNOPSIS
        Tests if a resource or user action is included in a Conditional Access policy.

    .DESCRIPTION
        This function checks if a resource (application) or user action is included in a
        Conditional Access policy. It enforces mutual exclusivity between applications and
        user actions - a context can't be both an application and a user action.

    .PARAMETER Policy
        The Conditional Access policy to evaluate.

    .PARAMETER ResourceContext
        The resource context for the sign-in scenario, containing application and/or user action information.

    .EXAMPLE
        Test-ResourceInclusions -Policy $policy -ResourceContext $ResourceContext
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$ResourceContext
    )

    # If no application conditions specified, all resources are included
    if (-not $Policy.Conditions.Applications) {
        Write-Verbose "No application conditions specified in policy, all resources are included"
        return @{
            Included = $true
            Reason   = "No application conditions specified"
        }
    }

    $includeApplications = $Policy.Conditions.Applications.IncludeApplications
    $includeUserActions = $Policy.Conditions.Applications.IncludeUserActions
    $includeAuthContexts = $Policy.Conditions.Applications.IncludeAuthenticationContextClassReferences

    # Detect what type of context we're evaluating (application or user action)
    # Check for mutual exclusivity - a context can't be both an application and a user action
    $isUserAction = [bool]$ResourceContext.UserAction
    $isApplication = [bool]$ResourceContext.AppId -and -not $isUserAction

    # Special case - if no includes are specified, nothing is included
    if ((-not $includeApplications -or $includeApplications.Count -eq 0) -and
        (-not $includeUserActions -or $includeUserActions.Count -eq 0) -and
        (-not $includeAuthContexts -or $includeAuthContexts.Count -eq 0)) {
        Write-Verbose "No application/action/context includes specified, no resources are included"
        return @{
            Included = $false
            Reason   = "No includes specified"
        }
    }

    # If this is a user action context but the policy only includes applications, not included
    if ($isUserAction -and $includeApplications -and -not $includeUserActions) {
        Write-Verbose "Resource is a user action, but policy only includes applications"
        return @{
            Included = $false
            Reason   = "Policy includes applications, not user actions"
        }
    }

    # If this is an application context but the policy only includes user actions, not included
    if ($isApplication -and $includeUserActions -and -not $includeApplications) {
        Write-Verbose "Resource is an application, but policy only includes user actions"
        return @{
            Included = $false
            Reason   = "Policy includes user actions, not applications"
        }
    }

    # User Action Check - if this is a user action, use the dedicated function
    if ($isUserAction) {
        $userActionContext = @{
            UserAction = $ResourceContext.UserAction
        }
        $userActionResult = Test-UserActionInScope -Policy $Policy -UserActionContext $userActionContext

        return @{
            Included = $userActionResult.InScope
            Reason   = $userActionResult.Reason
        }
    }

    # Application Checks - only execute if this is an application context
    if ($isApplication) {
        # Check if all applications are included
        Write-Verbose "Checking for AllApps special value in: $($includeApplications -join ', ')"
        $allAppsResult = Test-SpecialValueInsensitive -Collection $includeApplications -ValueType "AllApps"
        Write-Verbose "AllApps check result: $allAppsResult"

        if ($allAppsResult) {
            Write-Verbose "All applications included in policy"
            return @{
                Included = $true
                Reason   = "All applications included"
            }
        }

        # Check for Office365 special value
        if ((Test-SpecialValueInsensitive -Collection $includeApplications -ValueType "Office365Apps") -and $ResourceContext.IsOffice365) {
            Write-Verbose "Office365 application included in policy"
            return @{
                Included = $true
                Reason   = "Office365 application included"
            }
        }

        # Check if app is included
        if ($includeApplications -and $ResourceContext.AppId) {
            Write-Verbose "Checking included applications: $($includeApplications -join ', ')"

            # Case-insensitive comparison
            $appId = $ResourceContext.AppId.ToLower()

            foreach ($includedApp in $includeApplications) {
                if ($appId -eq $includedApp.ToLower()) {
                    Write-Verbose "Application explicitly included: $includedApp"
                    return @{
                        Included = $true
                        Reason   = "Application explicitly included"
                    }
                }
            }
        }

        # Application is not included in any inclusion list
        return @{
            Included = $false
            Reason   = "Application not in any inclusion lists"
        }
    }

    # Check for Authentication Context inclusions if present
    if ($includeAuthContexts -and $ResourceContext.AuthenticationContext) {
        Write-Verbose "Checking included authentication contexts: $($includeAuthContexts -join ', ')"

        if ($includeAuthContexts -contains $ResourceContext.AuthenticationContext) {
            Write-Verbose "Authentication context explicitly included: $($ResourceContext.AuthenticationContext)"
            return @{
                Included = $true
                Reason   = "Authentication context explicitly included"
            }
        }
    }

    # Resource is not included in any inclusion list
    return @{
        Included = $false
        Reason   = "Resource not in any inclusion lists"
    }
}

function Test-NetworkInScope {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$LocationContext
    )

    Write-Verbose "Testing network scope for policy: $($Policy.DisplayName)"
    Write-Verbose "IP: $($LocationContext.IpAddress), Named Location ID: $($LocationContext.NamedLocationId), Country: $($LocationContext.CountryCode), Trusted: $($LocationContext.IsTrustedLocation)"

    # Debug the locations object type
    $locationsType = if ($null -eq $Policy.Conditions.Locations) { "null" } else { $Policy.Conditions.Locations.GetType().Name }
    Write-Verbose "Locations condition type: $locationsType"

    # If locations is null in the policy, it means the condition is not set at all (equivalent to "All")
    if ($null -eq $Policy.Conditions.Locations) {
        Write-Verbose "Locations condition is null in policy, all locations in scope"
        return @{
            InScope = $true
            Reason  = "Location condition not configured in policy"
        }
    }

    # Handle case where Locations is an empty object without Include/Exclude properties
    if (-not $Policy.Conditions.Locations.PSObject.Properties.Name -contains "IncludeLocations" -and
        -not $Policy.Conditions.Locations.PSObject.Properties.Name -contains "ExcludeLocations") {
        Write-Verbose "Locations condition has no include/exclude properties, all locations in scope"
        return @{
            InScope = $true
            Reason  = "No location conditions specified"
        }
    }

    $includeLocations = $Policy.Conditions.Locations.IncludeLocations
    $excludeLocations = $Policy.Conditions.Locations.ExcludeLocations

    # If no locations specified in the conditions, location is in scope
    if ((-not $includeLocations -or $includeLocations.Count -eq 0) -and
        (-not $excludeLocations -or $excludeLocations.Count -eq 0)) {
        Write-Verbose "No specific locations included or excluded, all locations in scope"
        return @{
            InScope = $true
            Reason  = "No specific locations included or excluded"
        }
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

    # Check if location is explicitly excluded - can skip this if no IP/location specified
    if ($excludeLocations -and $excludeLocations.Count -gt 0 -and
        ($LocationContext.IpAddress -or $LocationContext.NamedLocationId -or $LocationContext.CountryCode)) {
        # Check exclusions only if we have something to check against
        foreach ($location in $excludeLocations) {
            if ($location -eq "All") {
                Write-Verbose "All locations excluded in policy"
                return @{
                    InScope = $false
                    Reason  = "All locations excluded"
                }
            }

            if ($LocationContext.IpAddress -and (Test-IpInNamedLocation -IpAddress $LocationContext.IpAddress -LocationId $location)) {
                Write-Verbose "Location explicitly excluded by IP address"
                return @{
                    InScope = $false
                    Reason  = "Location explicitly excluded"
                }
            }

            if ($LocationContext.NamedLocationId -and $LocationContext.NamedLocationId -eq $location) {
                Write-Verbose "Named location explicitly excluded: $($LocationContext.NamedLocationId)"
                return @{
                    InScope = $false
                    Reason  = "Named location explicitly excluded"
                }
            }
        }
    }

    # Check for inclusion - first see if All is specified
    if ($includeLocations) {
        foreach ($location in $includeLocations) {
            if ($location -eq "All") {
                Write-Verbose "All locations included in policy"
                return @{
                    InScope = $true
                    Reason  = "All locations included"
                }
            }
        }
    }

    # If there are no inclusion criteria at all, all locations are included
    if (-not $includeLocations -or $includeLocations.Count -eq 0) {
        Write-Verbose "No inclusion criteria for locations, all locations included by default"
        return @{
            InScope = $true
            Reason  = "No inclusion criteria for locations"
        }
    }

    # If we have inclusion criteria but no location information provided, default to in scope
    # This is a simplification for the WhatIf tool - in a real implementation, you might want
    # more nuanced behavior here
    if ($includeLocations.Count -gt 0 -and
        -not $LocationContext.IpAddress -and
        -not $LocationContext.NamedLocationId -and
        -not $LocationContext.CountryCode) {
        Write-Verbose "No location information provided, defaulting to in scope"
        return @{
            InScope = $true
            Reason  = "No location information provided, assuming in scope"
        }
    }

    # Now check if the provided location is included
    if ($includeLocations.Count -gt 0 -and
        ($LocationContext.IpAddress -or $LocationContext.NamedLocationId -or $LocationContext.CountryCode)) {
        # Check inclusions only if we have something to check against
        foreach ($location in $includeLocations) {
            if ($LocationContext.IpAddress -and (Test-IpInNamedLocation -IpAddress $LocationContext.IpAddress -LocationId $location)) {
                Write-Verbose "Location explicitly included by IP address"
                return @{
                    InScope = $true
                    Reason  = "Location explicitly included"
                }
            }

            if ($LocationContext.NamedLocationId -and $LocationContext.NamedLocationId -eq $location) {
                Write-Verbose "Named location explicitly included: $($LocationContext.NamedLocationId)"
                return @{
                    InScope = $true
                    Reason  = "Named location explicitly included"
                }
            }
        }

        # If we get here, the location wasn't in any of the include lists
        Write-Verbose "Location not in any inclusion lists"
        return @{
            InScope = $false
            Reason  = "Location not in any inclusion lists"
        }
    }

    # If we somehow get here (defensive programming)
    Write-Verbose "Unexpected location evaluation result, defaulting to in scope"
    return @{
        InScope = $true
        Reason  = "Unexpected location evaluation result, assuming in scope"
    }
}

function Test-ClientAppInScope {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$ResourceContext
    )

    Write-Verbose "Testing client app scope for policy: $($Policy.DisplayName)"
    Write-Verbose "Client app type: $($ResourceContext.ClientAppType)"

    # Explicitly debug the ClientAppTypes value
    $clientAppTypesDebug = if ($null -eq $Policy.Conditions.ClientAppTypes) {
        "null"
    }
    elseif ($Policy.Conditions.ClientAppTypes.Count -eq 0) {
        "empty array"
    }
    else {
        $Policy.Conditions.ClientAppTypes -join ", "
    }
    Write-Verbose "ClientAppTypes in policy: [$clientAppTypesDebug]"

    # If no client app types specified or null, all client apps are in scope
    if ($null -eq $Policy.Conditions.ClientAppTypes -or $Policy.Conditions.ClientAppTypes.Count -eq 0) {
        Write-Verbose "No client app types specified in policy, all client apps in scope"
        return @{
            InScope = $true
            Reason  = "No client app types specified"
        }
    }

    # Check if all client apps are included (case-insensitive check for "all" or "All")
    foreach ($clientAppType in $Policy.Conditions.ClientAppTypes) {
        Write-Verbose "Checking client app type from policy: '$clientAppType'"
        if ($clientAppType -ieq "all") {
            Write-Verbose "All client app types included in policy ('all' found)"
            return @{
                InScope = $true
                Reason  = "All client app types included"
            }
        }
    }

    # If client app type is not specified in the context
    if (-not $ResourceContext.ClientAppType) {
        Write-Verbose "No client app type specified in context, but will continue evaluation"
        # If the policy has the 'all' special value (case-insensitive)
        if ($Policy.Conditions.ClientAppTypes | Where-Object { $_ -ieq "all" }) {
            Write-Verbose "Policy includes 'all' client app types"
            return @{
                InScope = $true
                Reason  = "All client app types included by policy"
            }
        }
        return @{
            InScope = $true
            Reason  = "No client app type specified, default to in scope"
        }
    }

    # Check if client app type is explicitly included (case-insensitive)
    foreach ($clientAppType in $Policy.Conditions.ClientAppTypes) {
        if ($ResourceContext.ClientAppType -ieq $clientAppType) {
            Write-Verbose "Client app type explicitly included: $clientAppType"
            return @{
                InScope = $true
                Reason  = "Client app type explicitly included"
            }
        }
    }

    # For the 'all' case with specified client app type (handles both 'all' and 'All' case-insensitive)
    if ($Policy.Conditions.ClientAppTypes | Where-Object { $_ -ieq "all" }) {
        Write-Verbose "Client app type '$($ResourceContext.ClientAppType)' included by 'all' value"
        return @{
            InScope = $true
            Reason  = "Client app type included by 'all' value"
        }
    }

    Write-Verbose "Client app type not in scope: $($ResourceContext.ClientAppType)"
    Write-Verbose "Policy requires one of: $($Policy.Conditions.ClientAppTypes -join ', ')"
    return @{
        InScope = $false
        Reason  = "Client app type '$($ResourceContext.ClientAppType)' not in the required types: $($Policy.Conditions.ClientAppTypes -join ', ')"
    }
}

function Test-DevicePlatformInScope {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$DeviceContext
    )

    Write-Verbose "Testing device platform scope for policy: $($Policy.DisplayName)"
    Write-Verbose "Device platform: $($DeviceContext.Platform)"

    # Debug the platforms object type
    $platformsType = if ($null -eq $Policy.Conditions.Platforms) { "null" } else { $Policy.Conditions.Platforms.GetType().Name }
    Write-Verbose "Platforms condition type: $platformsType"

    # If platforms is null in the policy, it means the condition is not set at all (equivalent to "All")
    if ($null -eq $Policy.Conditions.Platforms) {
        Write-Verbose "Platforms condition is null in policy, all platforms in scope"
        return @{
            InScope = $true
            Reason  = "No platform condition set (null)"
        }
    }

    # Handle case where Platforms is an empty object without Include/Exclude properties
    if (-not $Policy.Conditions.Platforms.PSObject.Properties.Name -contains "IncludePlatforms" -and
        -not $Policy.Conditions.Platforms.PSObject.Properties.Name -contains "ExcludePlatforms") {
        Write-Verbose "Platforms condition has no include/exclude properties, all platforms in scope"
        return @{
            InScope = $true
            Reason  = "No platform conditions specified (empty object)"
        }
    }

    $includePlatforms = $Policy.Conditions.Platforms.IncludePlatforms
    $excludePlatforms = $Policy.Conditions.Platforms.ExcludePlatforms

    # If no platforms specified in the conditions, platform is in scope
    if ((-not $includePlatforms -or $includePlatforms.Count -eq 0) -and
        (-not $excludePlatforms -or $excludePlatforms.Count -eq 0)) {
        Write-Verbose "No specific platforms included or excluded, all platforms in scope"
        return @{
            InScope = $true
            Reason  = "No specific platforms included or excluded"
        }
    }

    # Check if platform is explicitly excluded
    if ($excludePlatforms -and $DeviceContext.Platform -and $DeviceContext.Platform -in $excludePlatforms) {
        Write-Verbose "Platform explicitly excluded: $($DeviceContext.Platform)"
        return @{
            InScope = $false
            Reason  = "Platform explicitly excluded"
        }
    }

    # The logic for inclusion

    # Check if all platforms are included using case-insensitive check
    if ($includePlatforms) {
        foreach ($platform in $includePlatforms) {
            if ($platform -ieq "All") {
                Write-Verbose "All platforms included in policy"
                return @{
                    InScope = $true
                    Reason  = "All platforms included"
                }
            }
        }
    }

    # Check if platform is explicitly included
    if ($includePlatforms -and $DeviceContext.Platform -and $DeviceContext.Platform -in $includePlatforms) {
        Write-Verbose "Platform explicitly included: $($DeviceContext.Platform)"
        return @{
            InScope = $true
            Reason  = "Platform explicitly included"
        }
    }
    elseif ($includePlatforms -and $includePlatforms.Count -gt 0 -and $DeviceContext.Platform) {
        # If there are inclusion criteria but this platform doesn't match
        Write-Verbose "Platform not in any inclusion list: $($DeviceContext.Platform)"
        Write-Verbose "Policy requires one of: $($includePlatforms -join ', ')"
        return @{
            InScope = $false
            Reason  = "Platform '$($DeviceContext.Platform)' not in required platforms: $($includePlatforms -join ', ')"
        }
    }
    elseif ($includePlatforms -and $includePlatforms.Count -gt 0 -and -not $DeviceContext.Platform) {
        # If there are inclusion criteria but no platform specified
        Write-Verbose "No platform specified in context, but policy requires specific platforms"
        return @{
            InScope = $false
            Reason  = "No platform specified in sign-in context"
        }
    }
    else {
        # If no include platforms specified, all platforms are included by default
        Write-Verbose "No inclusion criteria for platforms, all platforms included by default"
        return @{
            InScope = $true
            Reason  = "No inclusion criteria for platforms"
        }
    }
}

function Test-DeviceStateInScope {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$DeviceContext
    )

    Write-Verbose "Testing device state scope for policy: $($Policy.DisplayName)"
    Write-Verbose "Device compliance: $($DeviceContext.Compliance), Join type: $($DeviceContext.JoinType)"

    # Debug the devices object type and value
    $devicesType = if ($null -eq $Policy.Conditions.Devices) { "null" } else { $Policy.Conditions.Devices.GetType().Name }
    Write-Verbose "Devices condition type: $devicesType"

    # If devices condition is null or empty, all device states are in scope
    # More permissive check covering multiple scenarios
    if ($null -eq $Policy.Conditions.Devices -or
        [string]::IsNullOrEmpty($Policy.Conditions.Devices) -or
        $Policy.Conditions.Devices -eq "null" -or
        ($Policy.Conditions.Devices -is [PSCustomObject] -and
        -not $Policy.Conditions.Devices.PSObject.Properties.Name) -or
        ($Policy.Conditions.Devices -is [Hashtable] -and
        $Policy.Conditions.Devices.Count -eq 0)) {
        Write-Verbose "Device state condition is null/empty in policy, all device states in scope"
        return @{
            InScope = $true
            Reason  = "No device state condition set (null)"
        }
    }

    # If no device state properties are defined, all device states are in scope
    if (-not ($Policy.Conditions.Devices.PSObject.Properties.Name -contains "DeviceFilter" -or
            $Policy.Conditions.Devices.PSObject.Properties.Name -contains "DeviceComplianceRestriction" -or
            $Policy.Conditions.Devices.PSObject.Properties.Name -contains "DeviceJoinRestriction")) {
        Write-Verbose "No device state properties defined in policy, all device states in scope"
        return @{
            InScope = $true
            Reason  = "No device state conditions defined"
        }
    }

    # Since this is a WhatIf implementation and full device filter evaluation
    # would be complex, we'll use a simplified approach

    # If there's a device filter rule, we'll log it but assume it's satisfied
    if ($Policy.Conditions.Devices.DeviceFilter) {
        $filterRule = $Policy.Conditions.Devices.DeviceFilter.Rule
        Write-Verbose "Device filter rule found: $filterRule"
        Write-Verbose "For WhatIf purposes, assuming device filter rule is satisfied"
    }

    # Handle specific compliance requirements
    if ($Policy.Conditions.Devices.DeviceComplianceRestriction -and
        $Policy.Conditions.Devices.DeviceComplianceRestriction.IsCompliant -eq $true -and
        $DeviceContext.Compliance -ne $true) {
        Write-Verbose "Policy requires compliant device, but device is not compliant"
        return @{
            InScope = $false
            Reason  = "Policy requires compliant device"
        }
    }

    # Handle join type requirements (simplified)
    if ($Policy.Conditions.Devices.DeviceJoinRestriction -and
        $Policy.Conditions.Devices.DeviceJoinRestriction.JoinType -and
        $Policy.Conditions.Devices.DeviceJoinRestriction.JoinType -ne $DeviceContext.JoinType) {
        Write-Verbose "Policy requires join type: $($Policy.Conditions.Devices.DeviceJoinRestriction.JoinType), but device has: $($DeviceContext.JoinType)"
        return @{
            InScope = $false
            Reason  = "Policy requires join type: $($Policy.Conditions.Devices.DeviceJoinRestriction.JoinType)"
        }
    }

    Write-Verbose "Device state is in scope based on simplified WhatIf evaluation"
    return @{
        InScope = $true
        Reason  = "Device state requirements satisfied (simplified for WhatIf)"
    }
}

function Test-UserRiskLevelInScope {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$RiskContext
    )

    Write-Verbose "Testing user risk level for policy: $($Policy.DisplayName)"
    Write-Verbose "User risk level: $($RiskContext.UserRiskLevel)"

    # If user risk levels array is null or empty, all risk levels are in scope
    if ($null -eq $Policy.Conditions.UserRiskLevels -or
        $Policy.Conditions.UserRiskLevels.Count -eq 0 -or
        ($Policy.Conditions.UserRiskLevels | Where-Object { $_ -ieq "none" })) {
        Write-Verbose "No user risk levels specified in policy or 'none' level included, all risk levels in scope"
        return @{
            InScope = $true
            Reason  = "No user risk level condition set"
        }
    }

    # Log what risk levels are required by the policy
    Write-Verbose "Policy requires one of these user risk levels: $($Policy.Conditions.UserRiskLevels -join ', ')"

    # Check if user risk level is included
    if ($RiskContext.UserRiskLevel -in $Policy.Conditions.UserRiskLevels) {
        Write-Verbose "User risk level in scope: $($RiskContext.UserRiskLevel)"
        return @{
            InScope = $true
            Reason  = "User risk level '$($RiskContext.UserRiskLevel)' matches required level"
        }
    }

    # If no risk level specified in context but policy requires one
    if ([string]::IsNullOrEmpty($RiskContext.UserRiskLevel) -and ($Policy.Conditions.UserRiskLevels -contains "none" -or $Policy.Conditions.UserRiskLevels -contains "None")) {
        Write-Verbose "No user risk level is equivalent to 'none', which is accepted by the policy"
        return @{
            InScope = $true
            Reason  = "No risk is equivalent to 'none' risk level"
        }
    }

    if ([string]::IsNullOrEmpty($RiskContext.UserRiskLevel) -and $Policy.Conditions.UserRiskLevels.Count -gt 0) {
        Write-Verbose "No user risk level specified in context, but policy requires specific levels"
        return @{
            InScope = $false
            Reason  = "No user risk level provided, but policy requires: $($Policy.Conditions.UserRiskLevels -join ', ')"
        }
    }

    Write-Verbose "User risk level not in scope: $($RiskContext.UserRiskLevel)"
    return @{
        InScope = $false
        Reason  = "User risk level '$($RiskContext.UserRiskLevel)' not in required levels: $($Policy.Conditions.UserRiskLevels -join ', ')"
    }
}

function Test-SignInRiskLevelInScope {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$RiskContext
    )

    Write-Verbose "Testing sign-in risk level for policy: $($Policy.DisplayName)"
    Write-Verbose "Sign-in risk level: $($RiskContext.SignInRiskLevel)"

    # If sign-in risk levels array is null or empty, all risk levels are in scope
    if ($null -eq $Policy.Conditions.SignInRiskLevels -or
        $Policy.Conditions.SignInRiskLevels.Count -eq 0 -or
        ($Policy.Conditions.SignInRiskLevels | Where-Object { $_ -ieq "none" })) {
        Write-Verbose "No sign-in risk levels specified in policy or 'none' level included, all risk levels in scope"
        return @{
            InScope = $true
            Reason  = "No sign-in risk level condition set"
        }
    }

    # Log what risk levels are required by the policy
    Write-Verbose "Policy requires one of these sign-in risk levels: $($Policy.Conditions.SignInRiskLevels -join ', ')"

    # Check if sign-in risk level is included
    if ($RiskContext.SignInRiskLevel -in $Policy.Conditions.SignInRiskLevels) {
        Write-Verbose "Sign-in risk level in scope: $($RiskContext.SignInRiskLevel)"
        return @{
            InScope = $true
            Reason  = "Sign-in risk level '$($RiskContext.SignInRiskLevel)' matches required level"
        }
    }

    # If no risk level specified in context but policy requires one
    if ([string]::IsNullOrEmpty($RiskContext.SignInRiskLevel) -and ($Policy.Conditions.SignInRiskLevels -contains "none" -or $Policy.Conditions.SignInRiskLevels -contains "None")) {
        Write-Verbose "No sign-in risk level is equivalent to 'none', which is accepted by the policy"
        return @{
            InScope = $true
            Reason  = "No risk is equivalent to 'none' risk level"
        }
    }

    if ([string]::IsNullOrEmpty($RiskContext.SignInRiskLevel) -and $Policy.Conditions.SignInRiskLevels.Count -gt 0) {
        Write-Verbose "No sign-in risk level specified in context, but policy requires specific levels"
        return @{
            InScope = $false
            Reason  = "No sign-in risk level provided, but policy requires: $($Policy.Conditions.SignInRiskLevels -join ', ')"
        }
    }

    Write-Verbose "Sign-in risk level not in scope: $($RiskContext.SignInRiskLevel)"
    return @{
        InScope = $false
        Reason  = "Sign-in risk level '$($RiskContext.SignInRiskLevel)' not in required levels: $($Policy.Conditions.SignInRiskLevels -join ', ')"
    }
}


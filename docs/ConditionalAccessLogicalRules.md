# Conditional Access Logical Rules for PowerShell WhatIf Tool

## Policy Evaluation Logic

The following rules define how conditional access policies are evaluated in our WhatIf tool:

### 1. Policy Application Determination

A policy applies to a sign-in scenario if all of the following conditions are true:

```powershell
$policyApplies = (
    $userIsInScope -and
    $resourceIsInScope -and
    $networkIsInScope -and
    $clientAppIsInScope -and
    $devicePlatformIsInScope -and
    $deviceStateIsInScope -and
    $signInRiskIsInScope -and
    $userRiskIsInScope
)
```

### 2. User Scope Evaluation

```powershell
$userIsInScope = (
    # User is in included users/groups/roles
    ($user.Id -in $policy.Conditions.Users.IncludeUsers) -or
    (Compare-Object $user.MemberOf $policy.Conditions.Users.IncludeGroups -IncludeEqual -ExcludeDifferent) -or
    (Compare-Object $user.DirectoryRoles $policy.Conditions.Users.IncludeRoles -IncludeEqual -ExcludeDifferent)
) -and (
    # User is NOT in excluded users/groups/roles
    ($user.Id -notin $policy.Conditions.Users.ExcludeUsers) -and
    -not (Compare-Object $user.MemberOf $policy.Conditions.Users.ExcludeGroups -IncludeEqual -ExcludeDifferent) -and
    -not (Compare-Object $user.DirectoryRoles $policy.Conditions.Users.ExcludeRoles -IncludeEqual -ExcludeDifferent)
)
```

### 3. Cloud App Scope Evaluation

```powershell
$resourceIsInScope = (
    # App is in included apps OR all apps are included
    ($policy.Conditions.Applications.IncludeApplications -contains "All") -or
    ($resource.AppId -in $policy.Conditions.Applications.IncludeApplications)
) -and (
    # App is NOT in excluded apps
    ($resource.AppId -notin $policy.Conditions.Applications.ExcludeApplications)
)
```

### 4. Network Location Evaluation

```powershell
$networkIsInScope = (
    # All locations included OR IP is in included locations
    ($policy.Conditions.Locations.IncludeLocations -contains "All") -or
    ($signInIp -in $policy.Conditions.Locations.IncludeLocations)
) -and (
    # IP is NOT in excluded locations
    ($signInIp -notin $policy.Conditions.Locations.ExcludeLocations)
)
```

### 5. Client App Evaluation

```powershell
$clientAppIsInScope = (
    # All client apps included OR specific client app is included
    ($policy.Conditions.ClientAppTypes -contains "All") -or
    ($clientAppType -in $policy.Conditions.ClientAppTypes)
)
```

### 6. Device Platform Evaluation

```powershell
$devicePlatformIsInScope = (
    # All platforms included OR specific platform is included
    ($policy.Conditions.Platforms.IncludePlatforms -contains "All") -or
    ($devicePlatform -in $policy.Conditions.Platforms.IncludePlatforms)
) -and (
    # Platform is NOT in excluded platforms
    ($devicePlatform -notin $policy.Conditions.Platforms.ExcludePlatforms)
)
```

### 7. Device State Evaluation

```powershell
$deviceStateIsInScope = 
    # No device filters specified, OR device matches filters
    (-not $policy.Conditions.Devices.DeviceFilter) -or
    (Evaluate-DeviceFilter -Device $device -FilterRule $policy.Conditions.Devices.DeviceFilter)
```

### 8. Risk Level Evaluation

```powershell
$signInRiskIsInScope = 
    # No sign-in risk level specified, OR sign-in risk matches
    (-not $policy.Conditions.SignInRiskLevels) -or
    ($signInRiskLevel -in $policy.Conditions.SignInRiskLevels)

$userRiskIsInScope = 
    # No user risk level specified, OR user risk matches
    (-not $policy.Conditions.UserRiskLevels) -or
    ($userRiskLevel -in $policy.Conditions.UserRiskLevels)
```

## Grant Control Evaluation

Once a policy is determined to apply, the grant controls are evaluated:

### Block Access

```powershell
if ($policy.GrantControls.BuiltInControls -contains "Block") {
    # Access is blocked, no further policy evaluation needed
    return "Access blocked by policy: $($policy.DisplayName)"
}
```

### Grant Controls - Require All

```powershell
if ($policy.GrantControls.Operator -eq "AND") {
    # All controls must be satisfied
    $allControlsSatisfied = $true
    
    foreach ($control in $policy.GrantControls.BuiltInControls) {
        if (-not (Test-ControlSatisfied -Control $control -User $user -Device $device)) {
            $allControlsSatisfied = $false
            break
        }
    }
    
    if (-not $allControlsSatisfied) {
        # Return which controls need to be satisfied
        $missingControls = $policy.GrantControls.BuiltInControls | Where-Object { 
            -not (Test-ControlSatisfied -Control $_ -User $user -Device $device) 
        }
        return "Access requires satisfying all controls: $($missingControls -join ', ')"
    }
}
```

### Grant Controls - Require One

```powershell
if ($policy.GrantControls.Operator -eq "OR") {
    # At least one control must be satisfied
    $anyControlSatisfied = $false
    
    foreach ($control in $policy.GrantControls.BuiltInControls) {
        if (Test-ControlSatisfied -Control $control -User $user -Device $device) {
            $anyControlSatisfied = $true
            break
        }
    }
    
    if (-not $anyControlSatisfied) {
        # Return which controls could be satisfied
        return "Access requires satisfying at least one control: $($policy.GrantControls.BuiltInControls -join ', ')"
    }
}
```

## Session Control Application

After grant controls are satisfied, session controls are applied:

```powershell
$sessionControls = @()

if ($policy.SessionControls.ApplicationEnforced.IsEnabled) {
    $sessionControls += "App Enforced Restrictions"
}

if ($policy.SessionControls.CloudAppSecurity.IsEnabled) {
    $sessionControls += "Conditional Access App Control"
}

if ($policy.SessionControls.SignInFrequency.IsEnabled) {
    $sessionControls += "Sign-in frequency: $($policy.SessionControls.SignInFrequency.Value) $($policy.SessionControls.SignInFrequency.Type)"
}

if ($policy.SessionControls.PersistentBrowser.IsEnabled) {
    $sessionControls += "Persistent browser session: $($policy.SessionControls.PersistentBrowser.Mode)"
}

if ($sessionControls.Count -gt 0) {
    return "Access granted with session controls: $($sessionControls -join ', ')"
} else {
    return "Access granted"
}
```

## Policy Precedence and Combination

1. If any applicable policy blocks access, the user is blocked
2. If multiple policies apply, all must be satisfied
3. Grant controls are applied in the specified order
4. Session controls from all applicable policies are combined

```powershell
# Example evaluation logic
$blockingPolicies = $applicablePolicies | Where-Object { $_.GrantControls.BuiltInControls -contains "Block" }

if ($blockingPolicies.Count -gt 0) {
    return "Access blocked by policy: $($blockingPolicies[0].DisplayName)"
}

$grantControlResults = @()
foreach ($policy in $applicablePolicies) {
    $result = Evaluate-GrantControls -Policy $policy -User $user -Device $device
    $grantControlResults += $result
    
    if ($result.Blocked) {
        return "Access requirements not satisfied for policy: $($policy.DisplayName)"
    }
}

# If we get here, all grant controls are satisfied
$sessionControlResults = $applicablePolicies | ForEach-Object {
    Evaluate-SessionControls -Policy $_ -User $user -Device $device
}

return "Access granted with the following session controls: $($sessionControlResults -join ', ')"
```

## WhatIf Simulation Input Parameters

The WhatIf tool should accept these input parameters to simulate a sign-in scenario:

```powershell
# User parameters
$userId              # User object ID or UPN
$userGroups          # Groups the user belongs to
$userRoles           # Directory roles the user has
$userRiskLevel       # None, Low, Medium, High

# Resource parameters
$appId               # Application ID
$appDisplayName      # Application name

# Sign-in context
$ipAddress           # Sign-in IP address
$location            # Named location
$clientAppType       # Browser, Mobile, Desktop
$devicePlatform      # Windows, iOS, Android, macOS, Linux
$deviceCompliance    # Is device compliant? (true/false)
$deviceJoinType      # Azure AD Joined, Hybrid, Registered, Personal
$signInRiskLevel     # None, Low, Medium, High
$mfaAuthenticated    # Has MFA been performed? (true/false)
$approvedApplication # Is this an approved application? (true/false)
$appProtectionPolicy # Does the device have app protection? (true/false)
$browserPersistence  # Is browser persistence enabled? (true/false)
``` 
function Resolve-CAGrantControl {
    <#
    .SYNOPSIS
        Evaluates the grant controls for a Conditional Access policy that applies to a sign-in scenario.

    .DESCRIPTION
        This function evaluates the grant controls of a Conditional Access policy to determine
        if access is blocked, granted, or conditionally granted based on the policy's requirements
        and the provided user and device contexts.

        The evaluation follows Microsoft's implementation order with block priority:
        1. First check for block controls which immediately result in blocked access
        2. Process authentication strength if specified
        3. Evaluate remaining controls with unified AND/OR logic

    .PARAMETER Policy
        The Conditional Access policy to evaluate.

    .PARAMETER UserContext
        The user context for the sign-in scenario.

    .PARAMETER DeviceContext
        The device context for the sign-in scenario.

    .EXAMPLE
        Resolve-CAGrantControl -Policy $policy -UserContext $UserContext -DeviceContext $DeviceContext
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$UserContext,

        [Parameter(Mandatory = $true)]
        [object]$DeviceContext
    )

    # If no grant controls specified, access is granted
    if (-not $Policy.GrantControls -or -not $Policy.GrantControls.BuiltInControls) {
        Write-Verbose "No grant controls specified, access is granted"
        return @{
            AccessResult      = "Granted"
            Reason            = "No grant controls specified"
            SatisfiedControls = @()
            RequiredControls  = @()
        }
    }

    $controls = $Policy.GrantControls.BuiltInControls
    $operator = $Policy.GrantControls._Operator  # AND or OR

    # Always check block first - immediate exit if block is specified
    if ($controls -contains "block") {
        Write-Verbose "Block control is specified, access is blocked"
        return @{
            AccessResult      = "Blocked"
            Reason            = "Block control specified"
            SatisfiedControls = @()
            RequiredControls  = @()
        }
    }

    # Handle authentication strength as a special case with priority
    if ($Policy.GrantControls.AuthenticationStrength) {
        $authStrengthResult = Test-AuthenticationStrength -AuthStrength $Policy.GrantControls.AuthenticationStrength -UserContext $UserContext

        if (-not $authStrengthResult.Satisfied) {
            Write-Verbose "Authentication strength requirement not met: $($authStrengthResult.Reason)"
            return @{
                AccessResult        = "ConditionallyGranted"
                Reason              = "Authentication strength requirement not met"
                SatisfiedControls   = @()
                RequiredControls    = @("Authentication Strength: $($authStrengthResult.RequiredStrength)")
                AuthStrengthDetails = $authStrengthResult
            }
        }

        Write-Verbose "Authentication strength requirement satisfied: $($authStrengthResult.Reason)"

        # If no other controls specified, access is granted
        if (-not $controls -or $controls.Count -eq 0) {
            return @{
                AccessResult        = "Granted"
                Reason              = "Authentication strength requirement satisfied"
                SatisfiedControls   = @("Authentication Strength: $($authStrengthResult.RequiredStrength)")
                RequiredControls    = @()
                AuthStrengthDetails = $authStrengthResult
            }
        }
    }

    # Process all other controls
    $satisfiedControls = @()
    $requiredControls = @()

    # Process each control type
    foreach ($control in $controls) {
        $controlResult = Test-GrantControl -Control $control -UserContext $UserContext -DeviceContext $DeviceContext

        if ($controlResult.Satisfied) {
            $satisfiedControls += $controlResult.DisplayName
        }
        else {
            $requiredControls += $controlResult.DisplayName
        }
    }

    # Determine access result based on operator with unified logic
    $accessGranted = if ($operator -eq "OR") {
        # At least one control must be satisfied for OR
        $satisfiedControls.Count -gt 0
    }
    else {
        # All controls must be satisfied for AND (default)
        $requiredControls.Count -eq 0
    }

    if ($accessGranted) {
        return @{
            AccessResult      = "Granted"
            Reason            = "All required controls satisfied"
            SatisfiedControls = $satisfiedControls
            RequiredControls  = @()
        }
    }
    else {
        return @{
            AccessResult      = "ConditionallyGranted"
            Reason            = if ($operator -eq "OR") { "At least one control must be satisfied" } else { "All controls must be satisfied" }
            SatisfiedControls = $satisfiedControls
            RequiredControls  = $requiredControls
        }
    }
}

function Test-GrantControl {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Control,

        [Parameter(Mandatory = $true)]
        [object]$UserContext,

        [Parameter(Mandatory = $true)]
        [object]$DeviceContext
    )

    $controlMap = @{
        "mfa"                  = @{
            DisplayName  = "Multi-factor authentication"
            TestProperty = { param($u, $d) $u.MfaAuthenticated }
        }
        "compliantDevice"      = @{
            DisplayName  = "Compliant device"
            TestProperty = { param($u, $d) $d.Compliance }
        }
        "domainJoinedDevice"   = @{
            DisplayName  = "Hybrid Azure AD joined device"
            TestProperty = { param($u, $d) $d.JoinType -eq "Hybrid" }
        }
        "approvedApplication"  = @{
            DisplayName  = "Approved client app"
            TestProperty = { param($u, $d) $d.ApprovedApplication }
        }
        "compliantApplication" = @{
            DisplayName  = "App protection policy"
            TestProperty = { param($u, $d) $d.AppProtectionPolicy }
        }
        "passwordChange"       = @{
            DisplayName  = "Password change"
            TestProperty = { param($u, $d) $false } # For simulation, always require password change if specified
        }
        "terms"                = @{
            DisplayName  = "Terms of use"
            TestProperty = { param($u, $d) $false } # For simulation, always require terms if specified
        }
    }

    # Get control details from the map
    $controlDetails = $controlMap[$Control]

    # Default behavior for custom controls and unknown controls
    if (-not $controlDetails) {
        return @{
            Satisfied   = $false
            DisplayName = $Control
        }
    }

    # Test if the control is satisfied
    $satisfied = & $controlDetails.TestProperty $UserContext $DeviceContext

    return @{
        Satisfied   = $satisfied
        DisplayName = $controlDetails.DisplayName
    }
}

function Test-AuthenticationStrength {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$AuthStrength,

        [Parameter(Mandatory = $true)]
        [object]$UserContext
    )

    # This is a stub for now - will be implemented in Phase 2, Task 2.1
    # Currently always returns not satisfied to simulate the requirement

    return @{
        Satisfied        = $false
        RequiredStrength = $AuthStrength.displayName
    }
}
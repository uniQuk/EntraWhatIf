function Test-AuthenticationStrength {
    <#
    .SYNOPSIS
        Tests if a user's authentication methods satisfy an authentication strength policy.

    .DESCRIPTION
        This function evaluates if a user's authentication methods satisfy the authentication
        strength policy specified in a Conditional Access policy's grant controls.

        It supports:
        - Combination configurations for authentication methods
        - Authentication method verification against user's available methods
        - Compatible with different authentication strength policies

    .PARAMETER AuthStrength
        The authentication strength policy object from a policy's grant controls.

    .PARAMETER UserContext
        The user context containing authentication methods information.

    .EXAMPLE
        Test-AuthenticationStrength -AuthStrength $Policy.GrantControls.AuthenticationStrength -UserContext $UserContext
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$AuthStrength,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$UserContext
    )

    # If no authentication strength specified, consider it satisfied
    if (-not $AuthStrength) {
        Write-Verbose "No authentication strength specified, considered satisfied"
        return @{
            Satisfied        = $true
            Reason           = "No authentication strength required"
            RequiredStrength = $null
        }
    }

    # Extract strength policy details
    $strengthId = $AuthStrength.id
    $displayName = $AuthStrength.displayName

    Write-Verbose "Evaluating authentication strength: $displayName (ID: $strengthId)"

    # If user has no authentication methods, strength cannot be satisfied
    if (-not $UserContext -or -not $UserContext.AuthenticationMethods -or $UserContext.AuthenticationMethods.Count -eq 0) {
        Write-Verbose "User has no authentication methods, strength cannot be satisfied"
        return @{
            Satisfied        = $false
            Reason           = "User has no available authentication methods"
            RequiredStrength = $displayName
        }
    }

    # Try to get detailed strength policy if available
    $strengthPolicy = Get-AuthenticationStrengthPolicy -AuthenticationStrengthPolicyId $strengthId

    # If we couldn't get the detailed policy, do basic evaluation
    if (-not $strengthPolicy) {
        Write-Verbose "Could not retrieve detailed strength policy, using basic evaluation"

        # Check if user has MFA method
        $hasMfaMethod = $UserContext.AuthenticationMethods | Where-Object {
            $_.Type -in @("microsoftAuthenticator", "fido2SecurityKey", "softwareOath", "hardwareOath", "phoneAuthentication")
        }

        $satisfied = ($hasMfaMethod -ne $null)

        return @{
            Satisfied        = $satisfied
            Reason           = if ($satisfied) { "User has basic MFA method" } else { "User lacks required MFA method" }
            RequiredStrength = $displayName
        }
    }

    # Get user's authentication methods
    $userMethods = $UserContext.AuthenticationMethods | ForEach-Object { $_.Type }

    Write-Verbose "User authentication methods: $($userMethods -join ', ')"
    Write-Verbose "Required combinations: $($strengthPolicy.CombinationConfigurations.Count) configuration(s)"

    # Check if any combination is satisfied
    $satisfiedCombination = $false
    $combinationDetails = ""

    foreach ($combination in $strengthPolicy.CombinationConfigurations) {
        Write-Verbose "Checking combination: $($combination.DisplayName)"

        # Get the required method combinations for this configuration
        $requiredMethodCombinations = $combination.RequiredAuthenticationMethodCombinations

        foreach ($methodCombination in $requiredMethodCombinations) {
            Write-Verbose "Required methods for this combination: $($methodCombination -join ' AND ')"

            # Check if all methods in this combination are available to the user
            $allMethodsAvailable = $true
            foreach ($requiredMethod in $methodCombination) {
                if ($userMethods -notcontains $requiredMethod) {
                    $allMethodsAvailable = $false
                    Write-Verbose "User is missing required method: $requiredMethod"
                    break
                }
            }

            if ($allMethodsAvailable) {
                $satisfiedCombination = $true
                $combinationDetails = "$($combination.DisplayName) ($($methodCombination -join ' AND '))"
                Write-Verbose "Combination satisfied: $combinationDetails"
                break
            }
        }

        if ($satisfiedCombination) { break }
    }

    return @{
        Satisfied            = $satisfiedCombination
        Reason               = if ($satisfiedCombination) { "User satisfies authentication strength: $combinationDetails" } else { "User does not satisfy any authentication strength combination" }
        RequiredStrength     = $displayName
        RequiredCombinations = $strengthPolicy.CombinationConfigurations
    }
}

function Get-AuthenticationStrengthPolicy {
    <#
    .SYNOPSIS
        Retrieves an authentication strength policy by ID.

    .DESCRIPTION
        This function retrieves an authentication strength policy from Microsoft Graph API
        or from a cache. It returns the detailed policy with combination configurations.

    .PARAMETER AuthenticationStrengthPolicyId
        The ID of the authentication strength policy to retrieve.

    .EXAMPLE
        Get-AuthenticationStrengthPolicy -AuthenticationStrengthPolicyId "00000000-0000-0000-0000-000000000000"
    #>
    [CmdletBinding()]
    [OutputType([System.Object])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AuthenticationStrengthPolicyId
    )

    # Check if policy is in cache
    if ($script:AuthStrengthPoliciesCache -and $script:AuthStrengthPoliciesCache.ContainsKey($AuthenticationStrengthPolicyId)) {
        Write-Verbose "Retrieved authentication strength policy '$AuthenticationStrengthPolicyId' from cache"
        return $script:AuthStrengthPoliciesCache[$AuthenticationStrengthPolicyId]
    }

    try {
        # Retrieve authentication strength policy from Graph API
        $policy = Get-MgPolicyAuthenticationStrengthPolicy -AuthenticationStrengthPolicyId $AuthenticationStrengthPolicyId

        # Initialize cache if not exists
        if (-not $script:AuthStrengthPoliciesCache) {
            $script:AuthStrengthPoliciesCache = @{}
        }

        # Add to cache
        $script:AuthStrengthPoliciesCache[$AuthenticationStrengthPolicyId] = $policy

        return $policy
    }
    catch {
        Write-Warning "Error retrieving authentication strength policy '$AuthenticationStrengthPolicyId': $_"

        # Return a built-in policy for well-known IDs
        $builtInPolicy = Get-BuiltInAuthenticationStrengthPolicy -AuthenticationStrengthPolicyId $AuthenticationStrengthPolicyId
        if ($builtInPolicy) {
            return $builtInPolicy
        }

        return $null
    }
}

function Get-BuiltInAuthenticationStrengthPolicy {
    <#
    .SYNOPSIS
        Gets a built-in authentication strength policy based on its ID.

    .DESCRIPTION
        This function returns a built-in definition for well-known authentication
        strength policies when the Graph API is not available or returns an error.

    .PARAMETER AuthenticationStrengthPolicyId
        The ID of the authentication strength policy to retrieve.

    .EXAMPLE
        Get-BuiltInAuthenticationStrengthPolicy -AuthenticationStrengthPolicyId "00000000-0000-0000-0000-000000000001"
    #>
    [CmdletBinding()]
    [OutputType([System.Object])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AuthenticationStrengthPolicyId
    )

    # Map of built-in authentication strength policies with their IDs
    $builtInPolicies = @{
        # Microsoft Entra multifactor authentication
        "c1a4e2d5-a209-4524-bb83-b2ab066404a6" = @{
            Id                        = "c1a4e2d5-a209-4524-bb83-b2ab066404a6"
            DisplayName               = "Microsoft Entra multifactor authentication"
            Description               = "Require Microsoft Entra multifactor authentication"
            CombinationConfigurations = @(
                @{
                    DisplayName                              = "Microsoft Entra MFA"
                    RequiredAuthenticationMethodCombinations = @(
                        @("microsoftAuthenticator"),
                        @("softwareOath"),
                        @("hardwareOath"),
                        @("phoneAuthentication"),
                        @("fido2SecurityKey")
                    )
                }
            )
        }

        # Passwordless MFA
        "be5aa28e-21ea-4f11-9db4-0f6982c16fb6" = @{
            Id                        = "be5aa28e-21ea-4f11-9db4-0f6982c16fb6"
            DisplayName               = "Passwordless MFA"
            Description               = "Require passwordless MFA"
            CombinationConfigurations = @(
                @{
                    DisplayName                              = "Passwordless methods"
                    RequiredAuthenticationMethodCombinations = @(
                        @("windowsHelloForBusiness"),
                        @("fido2SecurityKey"),
                        @("microsoftAuthenticator")
                    )
                }
            )
        }

        # Phishing-resistant MFA
        "00000000-0000-0000-0000-000000000004" = @{
            Id                        = "00000000-0000-0000-0000-000000000004"
            DisplayName               = "Phishing-resistant MFA"
            Description               = "Require phishing-resistant MFA"
            CombinationConfigurations = @(
                @{
                    DisplayName                              = "Phishing-resistant methods"
                    RequiredAuthenticationMethodCombinations = @(
                        @("windowsHelloForBusiness"),
                        @("fido2SecurityKey")
                    )
                }
            )
        }
    }

    # Return the built-in policy if found
    if ($builtInPolicies.ContainsKey($AuthenticationStrengthPolicyId)) {
        return $builtInPolicies[$AuthenticationStrengthPolicyId]
    }

    # Return null if not found
    return $null
}
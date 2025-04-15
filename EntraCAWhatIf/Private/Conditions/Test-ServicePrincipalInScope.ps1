function Test-ServicePrincipalInScope {
    <#
    .SYNOPSIS
        Tests if a service principal is in scope for a Conditional Access policy.

    .DESCRIPTION
        This function evaluates if a service principal is in scope for a Conditional Access policy
        based on inclusion and exclusion rules specified in the policy.

    .PARAMETER Policy
        The Conditional Access policy to evaluate.

    .PARAMETER ServicePrincipalContext
        The service principal context for evaluation, containing ID, AppId, and other relevant properties.

    .EXAMPLE
        Test-ServicePrincipalInScope -Policy $policy -ServicePrincipalContext $servicePrincipalContext
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$ServicePrincipalContext
    )

    $result = @{
        InScope = $false
        Reason  = $null
    }

    # Extract service principal context information
    $servicePrincipalId = $ServicePrincipalContext.Id
    $servicePrincipalAppId = $ServicePrincipalContext.AppId
    $servicePrincipalDisplayName = $ServicePrincipalContext.DisplayName

    # First, check if the policy even applies to service principals
    # If policy only applies to users, then service principal is not in scope
    if ($Policy.Conditions.Users.IncludeUsers -and
        -not (Test-SpecialValue -Collection $Policy.Conditions.Users.IncludeUsers -ValueType "AllUsers") -and
        -not $Policy.Conditions.Users.IncludeServicePrincipals -and
        -not (Test-SpecialValue -Collection $Policy.Conditions.Users.IncludeServicePrincipals -ValueType "AllServicePrincipals")) {
        $result.Reason = "Policy only applies to users, not service principals"
        return $result
    }

    # Check exclusions first (always take precedence)
    # Check if service principal is explicitly excluded
    if ($Policy.Conditions.Users.ExcludeServicePrincipals -and
        ($Policy.Conditions.Users.ExcludeServicePrincipals -contains $servicePrincipalId -or
        $Policy.Conditions.Users.ExcludeServicePrincipals -contains $servicePrincipalAppId)) {
        $result.Reason = "Service principal explicitly excluded"
        return $result
    }

    # For the inclusion checks, we need to determine if the service principal is included

    # Case 1: All service principals are included
    if ((Test-SpecialValue -Collection $Policy.Conditions.Users.IncludeServicePrincipals -ValueType "AllServicePrincipals") -or
        (Test-SpecialValue -Collection $Policy.Conditions.Users.IncludeUsers -ValueType "AllUsers")) {
        $result.InScope = $true
        $result.Reason = "All service principals are included"
        return $result
    }

    # Case 2: Specific service principals are included
    if ($Policy.Conditions.Users.IncludeServicePrincipals -and
        ($Policy.Conditions.Users.IncludeServicePrincipals -contains $servicePrincipalId -or
        $Policy.Conditions.Users.IncludeServicePrincipals -contains $servicePrincipalAppId)) {
        $result.InScope = $true
        $result.Reason = "Service principal explicitly included"
        return $result
    }

    # Case 3: Policy has inclusion criteria, but this service principal doesn't match any
    if ($Policy.Conditions.Users.IncludeServicePrincipals -and $Policy.Conditions.Users.IncludeServicePrincipals.Count -gt 0) {
        $result.Reason = "Service principal not in any explicit inclusions"
        return $result
    }

    # If we made it here, the policy doesn't specifically include or exclude this service principal
    # Default to not in scope if there are specific inclusion criteria for other subjects
    if ($Policy.Conditions.Users.IncludeUsers -and $Policy.Conditions.Users.IncludeUsers.Count -gt 0 -and
        -not (Test-SpecialValue -Collection $Policy.Conditions.Users.IncludeUsers -ValueType "AllUsers")) {
        $result.Reason = "Policy includes specific users but not this service principal"
        return $result
    }

    # By default, if no specific inclusion criteria, assume in scope
    $result.InScope = $true
    $result.Reason = "No specific exclusion or inclusion criteria for service principals"
    return $result
}

# Export the function
Export-ModuleMember -Function Test-ServicePrincipalInScope
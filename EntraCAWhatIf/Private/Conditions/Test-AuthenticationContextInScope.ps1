function Test-AuthenticationContextInScope {
    <#
    .SYNOPSIS
        Checks if the provided authentication context is in scope for a Conditional Access policy.

    .DESCRIPTION
        This function evaluates whether a given authentication context class reference (ACCR)
        is in scope for a Conditional Access policy by checking inclusion and exclusion lists.
        It supports checking against both user-provided authentication contexts and those
        retrieved from the Microsoft Graph API.

    .PARAMETER Policy
        The Conditional Access policy to evaluate.

    .PARAMETER AuthenticationContext
        The authentication context object containing the authentication context class references.

    .EXAMPLE
        Test-AuthenticationContextInScope -Policy $policy -AuthenticationContext $authContext
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$AuthenticationContext
    )

    # Default result
    $result = @{
        InScope = $false
        Reason  = "Authentication context not evaluated"
    }

    # Get authentication contexts from policy
    $includeAuthenticationContexts = $Policy.Conditions.Applications.IncludeAuthenticationContextClassReferences
    $excludeAuthenticationContexts = $Policy.Conditions.Applications.ExcludeAuthenticationContextClassReferences

    # If neither include nor exclude lists are defined, consider in scope (not applicable)
    if (($null -eq $includeAuthenticationContexts -or $includeAuthenticationContexts.Count -eq 0) -and
        ($null -eq $excludeAuthenticationContexts -or $excludeAuthenticationContexts.Count -eq 0)) {
        $result.InScope = $true
        $result.Reason = "No authentication context requirements specified"
        return $result
    }

    # Handle the case when no authentication context is provided but policy requires one
    if ($null -eq $AuthenticationContext.ClassReference -and
        $includeAuthenticationContexts -and
        $includeAuthenticationContexts.Count -gt 0) {
        $result.InScope = $false
        $result.Reason = "Authentication context required but not provided"
        return $result
    }

    # Check exclusions first (if any of the contexts are excluded, policy doesn't apply)
    if ($excludeAuthenticationContexts -and
        $excludeAuthenticationContexts.Count -gt 0 -and
        $AuthenticationContext.ClassReference) {

        foreach ($contextRef in $AuthenticationContext.ClassReference) {
            if ($excludeAuthenticationContexts -contains $contextRef) {
                $result.InScope = $false
                $result.Reason = "Authentication context '$contextRef' is excluded"
                return $result
            }
        }
    }

    # Check inclusions (if no contexts are included, policy doesn't apply)
    if ($includeAuthenticationContexts -and $includeAuthenticationContexts.Count -gt 0) {
        $matchFound = $false

        # If authentication context is provided, check if it's in the inclusion list
        if ($AuthenticationContext.ClassReference) {
            foreach ($contextRef in $AuthenticationContext.ClassReference) {
                if ($includeAuthenticationContexts -contains $contextRef) {
                    $matchFound = $true
                    break
                }
            }
        }

        if (-not $matchFound) {
            $result.InScope = $false
            $result.Reason = "No matching authentication context found in inclusion list"
            return $result
        }
    }

    # If we reach here, authentication context is in scope
    $result.InScope = $true
    $result.Reason = "Authentication context is in scope"

    return $result
}

function Get-AuthenticationContextClassReferences {
    <#
    .SYNOPSIS
        Retrieves authentication context class references from Microsoft Graph.

    .DESCRIPTION
        This function retrieves the authentication context class references defined in the tenant
        from Microsoft Graph API. These can be used for evaluating Conditional Access policies
        that utilize authentication contexts.

    .EXAMPLE
        Get-AuthenticationContextClassReferences
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param ()

    try {
        # Check if we have cached authentication contexts
        if ($script:AuthenticationContextCache -and
            $script:AuthenticationContextCacheExpiry -gt (Get-Date)) {
            Write-Verbose "Using cached authentication contexts"
            return $script:AuthenticationContextCache
        }

        # Retrieve authentication contexts from Graph API
        Write-Verbose "Retrieving authentication contexts from Graph API"
        $authContexts = Get-MgBetaPolicyAuthenticationContextClassReference -ErrorAction Stop

        # Process and cache the results
        $contextMap = @{}
        foreach ($context in $authContexts) {
            $contextMap[$context.Id] = @{
                DisplayName = $context.DisplayName
                Description = $context.Description
                IsAvailable = $context.IsAvailable
            }
        }

        # Cache the results for 30 minutes
        $script:AuthenticationContextCache = $contextMap
        $script:AuthenticationContextCacheExpiry = (Get-Date).AddMinutes(30)

        return $contextMap
    }
    catch {
        Write-Warning "Failed to retrieve authentication contexts: $_"
        return @{}
    }
}

# Export functions
Export-ModuleMember -Function Test-AuthenticationContextInScope, Get-AuthenticationContextClassReferences
function Resolve-ServicePrincipalIdentity {
    <#
    .SYNOPSIS
        Resolves a service principal ID or app ID to full service principal details.

    .DESCRIPTION
        This function resolves a service principal by its ID, app ID, or display name
        to obtain the full service principal details for use in Conditional Access evaluation.

    .PARAMETER ServicePrincipalIdOrAppId
        The service principal object ID, application ID, or display name to resolve.

    .EXAMPLE
        Resolve-ServicePrincipalIdentity -ServicePrincipalIdOrAppId "00000000-0000-0000-0000-000000000000"

    .EXAMPLE
        Resolve-ServicePrincipalIdentity -ServicePrincipalIdOrAppId "Microsoft Graph"
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipalIdOrAppId
    )

    $result = @{
        Success      = $false
        Id           = $null
        AppId        = $null
        DisplayName  = $null
        ErrorMessage = $null
    }

    # Return early if empty string provided
    if ([string]::IsNullOrWhiteSpace($ServicePrincipalIdOrAppId)) {
        $result.ErrorMessage = "Service principal ID or app ID cannot be empty"
        return $result
    }

    try {
        # First try to get by Object ID (exact match)
        $servicePrincipal = Get-MgServicePrincipal -ServicePrincipalId $ServicePrincipalIdOrAppId -ErrorAction SilentlyContinue

        # If not found by ID, try by App ID
        if (-not $servicePrincipal) {
            $filter = "appId eq '$ServicePrincipalIdOrAppId'"
            $servicePrincipal = Get-MgServicePrincipal -Filter $filter -ErrorAction SilentlyContinue | Select-Object -First 1

            # If still not found, try by display name
            if (-not $servicePrincipal) {
                $filter = "displayName eq '$ServicePrincipalIdOrAppId'"
                $servicePrincipal = Get-MgServicePrincipal -Filter $filter -ErrorAction SilentlyContinue | Select-Object -First 1

                # Finally, try a partial display name match
                if (-not $servicePrincipal) {
                    $filter = "startswith(displayName, '$ServicePrincipalIdOrAppId')"
                    $servicePrincipal = Get-MgServicePrincipal -Filter $filter -ErrorAction SilentlyContinue | Select-Object -First 1
                }
            }
        }

        if ($servicePrincipal) {
            $result.Success = $true
            $result.Id = $servicePrincipal.Id
            $result.AppId = $servicePrincipal.AppId
            $result.DisplayName = $servicePrincipal.DisplayName
        }
        else {
            $result.ErrorMessage = "Service principal not found with ID, AppId, or DisplayName '$ServicePrincipalIdOrAppId'"
        }
    }
    catch {
        $result.ErrorMessage = "Error resolving service principal: $_"
    }

    return $result
}

# Export the function
Export-ModuleMember -Function Resolve-ServicePrincipalIdentity
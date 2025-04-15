function Test-SpecialValue {
    <#
    .SYNOPSIS
        Tests if a collection contains a special value from a predefined set.

    .DESCRIPTION
        This function checks if a collection contains any of the special values
        for a given value type. It handles case-sensitive checks where needed.

        Special values include:
        - AllUsers: "All" for user inclusion
        - AllApps: "All" for application inclusion
        - Office365Apps: "Office365" for Office 365 applications
        - AllLocations: "All" for locations
        - AllTrustedLocations: "AllTrusted" for trusted locations
        - AllPlatforms: "all" (lowercase) for device platforms
        - AllClientApps: "all" (lowercase) for client applications
        - GuestsOrExternalUsers: "GuestsOrExternalUsers" for external users

    .PARAMETER Collection
        The collection to check for special values.

    .PARAMETER ValueType
        The type of special value to check for.
        Valid options: AllUsers, AllApps, Office365Apps, AllLocations,
        AllTrustedLocations, AllPlatforms, AllClientApps, GuestsOrExternalUsers

    .EXAMPLE
        Test-SpecialValue -Collection $policy.Conditions.Applications.IncludeApplications -ValueType AllApps
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [array]$Collection,

        [Parameter(Mandatory = $true)]
        [ValidateSet(
            "AllUsers",
            "AllApps",
            "Office365Apps",
            "AllLocations",
            "AllTrustedLocations",
            "AllPlatforms",
            "AllClientApps",
            "GuestsOrExternalUsers",
            "AllServicePrincipals"
        )]
        [string]$ValueType
    )

    # If collection is null or empty, special values can't be present
    if ($null -eq $Collection -or $Collection.Count -eq 0) {
        return $false
    }

    # Define special values map with exact case sensitivity
    $specialValues = @{
        AllUsers              = @("All")
        AllApps               = @("All")
        Office365Apps         = @("Office365")
        AllLocations          = @("All")
        AllTrustedLocations   = @("AllTrusted")
        AllPlatforms          = @("all")  # Note lowercase
        AllClientApps         = @("all") # Note lowercase
        GuestsOrExternalUsers = @("GuestsOrExternalUsers")
        AllServicePrincipals  = @("All")
    }

    # Get the special values for the requested type
    $valuesForType = $specialValues[$ValueType]

    if ($null -eq $valuesForType) {
        Write-Error "Invalid value type: $ValueType"
        return $false
    }

    # Check if any of the special values are in the collection
    foreach ($value in $valuesForType) {
        # Case-sensitive check
        if ($Collection -ccontains $value) {
            Write-Verbose "Special value '$value' found for type '$ValueType'"
            return $true
        }
    }

    Write-Verbose "No special values found for type '$ValueType'"
    return $false
}

# Add a case-insensitive version for compatibility
function Test-SpecialValueInsensitive {
    <#
    .SYNOPSIS
        Tests if a collection contains a special value (case-insensitive).

    .DESCRIPTION
        This function performs a case-insensitive check if a collection contains
        any of the special values for a given value type.

    .PARAMETER Collection
        The collection to check for special values.

    .PARAMETER ValueType
        The type of special value to check for.
        Valid options: AllUsers, AllApps, Office365Apps, AllLocations,
        AllTrustedLocations, AllPlatforms, AllClientApps, GuestsOrExternalUsers

    .EXAMPLE
        Test-SpecialValueInsensitive -Collection $policy.Conditions.Applications.IncludeApplications -ValueType AllApps
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [array]$Collection,

        [Parameter(Mandatory = $true)]
        [ValidateSet(
            "AllUsers",
            "AllApps",
            "Office365Apps",
            "AllLocations",
            "AllTrustedLocations",
            "AllPlatforms",
            "AllClientApps",
            "GuestsOrExternalUsers",
            "AllServicePrincipals"
        )]
        [string]$ValueType
    )

    # If collection is null or empty, special values can't be present
    if ($null -eq $Collection -or $Collection.Count -eq 0) {
        return $false
    }

    # Define special values map
    $specialValues = @{
        AllUsers              = @("All", "all")
        AllApps               = @("All", "all")
        Office365Apps         = @("Office365", "office365")
        AllLocations          = @("All", "all")
        AllTrustedLocations   = @("AllTrusted", "alltrusted")
        AllPlatforms          = @("all", "All")
        AllClientApps         = @("all", "All")
        GuestsOrExternalUsers = @("GuestsOrExternalUsers", "guestsorexternalusers")
        AllServicePrincipals  = @("All", "all")
    }

    # Get the special values for the requested type
    $valuesForType = $specialValues[$ValueType]

    if ($null -eq $valuesForType) {
        Write-Error "Invalid value type: $ValueType"
        return $false
    }

    # Check if any of the special values are in the collection
    foreach ($value in $valuesForType) {
        foreach ($item in $Collection) {
            if ($item -ieq $value) {
                Write-Verbose "Special value '$value' found for type '$ValueType' (case-insensitive)"
                return $true
            }
        }
    }

    Write-Verbose "No special values found for type '$ValueType' (case-insensitive)"
    return $false
}
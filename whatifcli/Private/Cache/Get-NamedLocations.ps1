function Get-NamedLocations {
    <#
    .SYNOPSIS
        Retrieves and caches all named locations from Microsoft Graph API.

    .DESCRIPTION
        This function retrieves all named locations from Microsoft Graph API and caches them
        for efficient reuse. It supports both IP-based and country/region-based named locations.

        The function returns a hashtable with location IDs as keys for quick lookups.

    .PARAMETER ForceRefresh
        If specified, refreshes the cache even if it already exists.

    .PARAMETER CacheDurationMinutes
        The duration in minutes for which the cache remains valid. Default is 30 minutes.

    .EXAMPLE
        $namedLocations = Get-NamedLocations

    .EXAMPLE
        $namedLocations = Get-NamedLocations -ForceRefresh -CacheDurationMinutes 60
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $false)]
        [switch]$ForceRefresh,

        [Parameter(Mandatory = $false)]
        [int]$CacheDurationMinutes = 30
    )

    # Initialize cache if not exists
    if (-not $script:NamedLocationsCache) {
        $script:NamedLocationsCache = @{
            Locations      = @{}
            ExpirationTime = [DateTime]::MinValue
        }
    }

    # Check if cache is expired or force refresh requested
    $cacheExpired = [DateTime]::Now -gt $script:NamedLocationsCache.ExpirationTime
    if ($cacheExpired -or $ForceRefresh -or $script:NamedLocationsCache.Locations.Count -eq 0) {
        Write-Verbose "Refreshing named locations cache"

        try {
            # Get all named locations from Graph API
            $allLocations = Get-MgIdentityConditionalAccessNamedLocation -All

            # Clear existing cache
            $script:NamedLocationsCache.Locations = @{}

            # Process each location
            foreach ($location in $allLocations) {
                $processedLocation = ProcessNamedLocation -Location $location
                if ($processedLocation) {
                    $script:NamedLocationsCache.Locations[$location.Id] = $processedLocation
                }
            }

            # Set expiration time
            $script:NamedLocationsCache.ExpirationTime = [DateTime]::Now.AddMinutes($CacheDurationMinutes)

            Write-Verbose "Named locations cache refreshed with $($script:NamedLocationsCache.Locations.Count) locations"
        }
        catch {
            Write-Warning "Error retrieving named locations: $_"
            # If cache is empty, initialize with empty collection
            if ($script:NamedLocationsCache.Locations.Count -eq 0) {
                $script:NamedLocationsCache.Locations = @{}
            }
        }
    }
    else {
        Write-Verbose "Using cached named locations ($($script:NamedLocationsCache.Locations.Count) locations)"
    }

    return $script:NamedLocationsCache.Locations
}

function ProcessNamedLocation {
    <#
    .SYNOPSIS
        Processes a named location object for efficient lookup.

    .DESCRIPTION
        This function processes a named location object retrieved from the Graph API,
        extracting relevant properties and transforming it for efficient use.

    .PARAMETER Location
        The named location object from Graph API.

    .EXAMPLE
        ProcessNamedLocation -Location $location
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Location
    )

    try {
        # Common properties
        $processedLocation = @{
            Id               = $Location.Id
            DisplayName      = $Location.DisplayName
            CreatedDateTime  = $Location.CreatedDateTime
            ModifiedDateTime = $Location.AdditionalProperties.modifiedDateTime
            Type             = $null
            IsTrusted        = $false
            IpRanges         = @()
            CountryOrRegion  = @()
        }

        # Process IP-based named location
        if ($Location.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.ipNamedLocation") {
            $processedLocation.Type = "IP"
            $processedLocation.IsTrusted = $Location.AdditionalProperties.isTrusted

            # Process IP ranges
            if ($Location.AdditionalProperties.ipRanges) {
                foreach ($range in $Location.AdditionalProperties.ipRanges) {
                    # Handle different IP range types (IPv4, IPv6)
                    if ($range.'@odata.type' -eq "#microsoft.graph.iPv4CidrRange") {
                        $processedLocation.IpRanges += $range.cidrAddress
                    }
                    elseif ($range.'@odata.type' -eq "#microsoft.graph.iPv6CidrRange") {
                        $processedLocation.IpRanges += $range.cidrAddress
                    }
                    elseif ($range.'@odata.type' -eq "#microsoft.graph.iPv4Range") {
                        $processedLocation.IpRanges += "$($range.lowerAddress)-$($range.upperAddress)"
                    }
                    elseif ($range.'@odata.type' -eq "#microsoft.graph.iPv6Range") {
                        $processedLocation.IpRanges += "$($range.lowerAddress)-$($range.upperAddress)"
                    }
                }
            }
        }
        # Process country/region-based named location
        elseif ($Location.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.countryNamedLocation") {
            $processedLocation.Type = "CountryOrRegion"
            $processedLocation.CountryOrRegion = $Location.AdditionalProperties.countriesAndRegions
            $processedLocation.IncludeUnknownCountriesAndRegions = $Location.AdditionalProperties.includeUnknownCountriesAndRegions
        }

        return $processedLocation
    }
    catch {
        Write-Warning "Error processing named location $($Location.DisplayName): $_"
        return $null
    }
}

function Test-LocationIsTrusted {
    <#
    .SYNOPSIS
        Tests if a location is trusted.

    .DESCRIPTION
        This function determines if a location is trusted based on its configuration.
        It supports both location IDs and pre-processed location objects.

    .PARAMETER LocationId
        The ID of the named location to check.

    .PARAMETER NamedLocation
        The pre-processed named location object.

    .EXAMPLE
        Test-LocationIsTrusted -LocationId "a1b2c3d4-e5f6-7890-1234-567890abcdef"

    .EXAMPLE
        Test-LocationIsTrusted -NamedLocation $namedLocation
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = "ById")]
        [string]$LocationId,

        [Parameter(Mandatory = $false, ParameterSetName = "ByObject")]
        [object]$NamedLocation
    )

    try {
        if ($PSCmdlet.ParameterSetName -eq "ById") {
            # Get named locations if not already cached
            $locations = Get-NamedLocations

            if (-not $locations.ContainsKey($LocationId)) {
                Write-Verbose "Location ID '$LocationId' not found"
                return $false
            }

            $location = $locations[$LocationId]
        }
        else {
            $location = $NamedLocation
        }

        # Only IP-based locations can be trusted
        if ($location.Type -eq "IP") {
            return $location.IsTrusted
        }

        return $false
    }
    catch {
        Write-Warning "Error testing if location is trusted: $_"
        return $false
    }
}

function Test-LocationContainsIp {
    <#
    .SYNOPSIS
        Tests if a location contains a specific IP address.

    .DESCRIPTION
        This function determines if a named location contains a specific IP address.
        It supports CIDR notation and IP ranges.

    .PARAMETER LocationId
        The ID of the named location to check.

    .PARAMETER IpAddress
        The IP address to check.

    .PARAMETER NamedLocation
        The pre-processed named location object.

    .EXAMPLE
        Test-LocationContainsIp -LocationId "a1b2c3d4-e5f6-7890-1234-567890abcdef" -IpAddress "192.168.1.1"

    .EXAMPLE
        Test-LocationContainsIp -NamedLocation $namedLocation -IpAddress "192.168.1.1"
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = "ById")]
        [string]$LocationId,

        [Parameter(Mandatory = $true)]
        [string]$IpAddress,

        [Parameter(Mandatory = $false, ParameterSetName = "ByObject")]
        [object]$NamedLocation
    )

    try {
        if ($PSCmdlet.ParameterSetName -eq "ById") {
            # Get named locations if not already cached
            $locations = Get-NamedLocations

            if (-not $locations.ContainsKey($LocationId)) {
                Write-Verbose "Location ID '$LocationId' not found"
                return $false
            }

            $location = $locations[$LocationId]
        }
        else {
            $location = $NamedLocation
        }

        # Only IP-based locations can contain IP addresses
        if ($location.Type -ne "IP") {
            return $false
        }

        foreach ($ipRange in $location.IpRanges) {
            # Check if range is in CIDR notation
            if ($ipRange -match "^(.+)/(\d+)$") {
                $networkAddress = $matches[1]
                $cidrPrefix = [int]$matches[2]

                if (Test-IpInCidrRange -IpAddress $IpAddress -NetworkAddress $networkAddress -CidrPrefix $cidrPrefix) {
                    return $true
                }
            }
            # Check if range is a simple IP address (exact match)
            elseif ($ipRange -eq $IpAddress) {
                return $true
            }
            # Check if range is in start-end format
            elseif ($ipRange -match "^(.+)-(.+)$") {
                $startIp = $matches[1]
                $endIp = $matches[2]

                if (Test-IpInRange -IpAddress $IpAddress -StartIp $startIp -EndIp $endIp) {
                    return $true
                }
            }
        }

        return $false
    }
    catch {
        Write-Warning "Error testing if location contains IP: $_"
        return $false
    }
}

function Test-LocationContainsCountry {
    <#
    .SYNOPSIS
        Tests if a location contains a specific country/region.

    .DESCRIPTION
        This function determines if a named location contains a specific country/region.

    .PARAMETER LocationId
        The ID of the named location to check.

    .PARAMETER CountryCode
        The ISO 3166-1 alpha-2 country code to check.

    .PARAMETER NamedLocation
        The pre-processed named location object.

    .EXAMPLE
        Test-LocationContainsCountry -LocationId "a1b2c3d4-e5f6-7890-1234-567890abcdef" -CountryCode "US"

    .EXAMPLE
        Test-LocationContainsCountry -NamedLocation $namedLocation -CountryCode "US"
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = "ById")]
        [string]$LocationId,

        [Parameter(Mandatory = $true)]
        [string]$CountryCode,

        [Parameter(Mandatory = $false, ParameterSetName = "ByObject")]
        [object]$NamedLocation
    )

    try {
        if ($PSCmdlet.ParameterSetName -eq "ById") {
            # Get named locations if not already cached
            $locations = Get-NamedLocations

            if (-not $locations.ContainsKey($LocationId)) {
                Write-Verbose "Location ID '$LocationId' not found"
                return $false
            }

            $location = $locations[$LocationId]
        }
        else {
            $location = $NamedLocation
        }

        # Only country/region-based locations can contain countries
        if ($location.Type -ne "CountryOrRegion") {
            return $false
        }

        # Check if country is in the list
        if ($location.CountryOrRegion -contains $CountryCode) {
            return $true
        }

        # Check if unknown countries should be included
        if ([string]::IsNullOrEmpty($CountryCode) -and $location.IncludeUnknownCountriesAndRegions) {
            return $true
        }

        return $false
    }
    catch {
        Write-Warning "Error testing if location contains country: $_"
        return $false
    }
}

# Export all functions
Export-ModuleMember -Function Get-NamedLocations, Test-LocationIsTrusted, Test-LocationContainsIp, Test-LocationContainsCountry
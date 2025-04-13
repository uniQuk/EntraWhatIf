function Get-CacheManager {
    <#
    .SYNOPSIS
        Provides centralized cache management for the WhatIf CLI module.

    .DESCRIPTION
        This function creates and manages a central cache for various data types used by the WhatIf CLI.
        It provides functions for getting, setting, and clearing cached data with expiration periods.

    .PARAMETER Operation
        The cache operation to perform: Get, Set, Clear, or Info.

    .PARAMETER CacheType
        The type of data being cached (Policies, Groups, Locations, etc).

    .PARAMETER Key
        The unique identifier for the cached item.

    .PARAMETER Value
        The data to cache (for Set operation).

    .PARAMETER ExpirationMinutes
        How long the cached data should be valid (in minutes).

    .EXAMPLE
        # Get a cached policy
        Get-CacheManager -Operation Get -CacheType Policies -Key "policyId123"

    .EXAMPLE
        # Set group membership data in cache
        Get-CacheManager -Operation Set -CacheType GroupMemberships -Key "user-123" -Value $groupData -ExpirationMinutes 15

    .EXAMPLE
        # Clear location cache
        Get-CacheManager -Operation Clear -CacheType Locations

    .EXAMPLE
        # Get cache statistics
        Get-CacheManager -Operation Info
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Get', 'Set', 'Clear', 'Info')]
        [string]$Operation,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Policies', 'GroupMemberships', 'Locations', 'Users', 'ServicePrincipals', 'All')]
        [string]$CacheType = 'All',

        [Parameter(Mandatory = $false)]
        [string]$Key,

        [Parameter(Mandatory = $false)]
        [object]$Value,

        [Parameter(Mandatory = $false)]
        [int]$ExpirationMinutes = 30
    )

    # Initialize cache if it doesn't exist
    if (-not (Get-Variable -Name Cache -Scope Script -ErrorAction SilentlyContinue)) {
        $script:Cache = @{
            Policies          = @{}
            GroupMemberships  = @{}
            Locations         = @{}
            Users             = @{}
            ServicePrincipals = @{}
            Stats             = @{
                Hits        = 0
                Misses      = 0
                Sets        = 0
                LastCleared = [DateTime]::Now
            }
        }
    }

    # Add internal functions
    function Get-CacheItem {
        param ($Type, $ItemKey)

        if (-not $script:Cache[$Type].ContainsKey($ItemKey)) {
            $script:Cache.Stats.Misses++
            return $null
        }

        $cacheItem = $script:Cache[$Type][$ItemKey]

        # Check if the item has expired
        if ([DateTime]::Now -gt $cacheItem.ExpirationTime) {
            $script:Cache[$Type].Remove($ItemKey)
            $script:Cache.Stats.Misses++
            return $null
        }

        $script:Cache.Stats.Hits++
        return $cacheItem.Value
    }

    function Set-CacheItem {
        param ($Type, $ItemKey, $ItemValue, $Expiry)

        $expirationTime = [DateTime]::Now.AddMinutes($Expiry)

        $script:Cache[$Type][$ItemKey] = @{
            Value          = $ItemValue
            ExpirationTime = $expirationTime
            CachedTime     = [DateTime]::Now
        }

        $script:Cache.Stats.Sets++
    }

    function Clear-CacheType {
        param ($Type)

        if ($Type -eq 'All') {
            foreach ($cacheType in $script:Cache.Keys) {
                if ($cacheType -ne 'Stats') {
                    $script:Cache[$cacheType] = @{}
                }
            }
        }
        else {
            $script:Cache[$Type] = @{}
        }

        $script:Cache.Stats.LastCleared = [DateTime]::Now
    }

    function Get-CacheInfo {
        $cacheInfo = @{
            Stats      = $script:Cache.Stats.Clone()
            ItemCounts = @{}
        }

        foreach ($cacheType in $script:Cache.Keys) {
            if ($cacheType -ne 'Stats') {
                $cacheInfo.ItemCounts[$cacheType] = $script:Cache[$cacheType].Count

                # Count expired items
                $expiredCount = 0
                foreach ($key in $script:Cache[$cacheType].Keys) {
                    if ([DateTime]::Now -gt $script:Cache[$cacheType][$key].ExpirationTime) {
                        $expiredCount++
                    }
                }

                $cacheInfo.ItemCounts["$($cacheType)Expired"] = $expiredCount
            }
        }

        return $cacheInfo
    }

    # Process the requested operation
    switch ($Operation) {
        'Get' {
            if (-not $CacheType -or -not $Key) {
                throw "CacheType and Key are required for Get operation"
            }
            return Get-CacheItem -Type $CacheType -ItemKey $Key
        }
        'Set' {
            if (-not $CacheType -or -not $Key -or $null -eq $Value) {
                throw "CacheType, Key, and Value are required for Set operation"
            }
            Set-CacheItem -Type $CacheType -ItemKey $Key -ItemValue $Value -Expiry $ExpirationMinutes
        }
        'Clear' {
            Clear-CacheType -Type $CacheType
        }
        'Info' {
            return Get-CacheInfo
        }
    }
}

Export-ModuleMember -Function Get-CacheManager
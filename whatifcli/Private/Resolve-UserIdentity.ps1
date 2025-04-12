function Resolve-UserIdentity {
    <#
    .SYNOPSIS
        Resolves user identities between GUIDs and user principal names (UPNs)

    .DESCRIPTION
        This function takes either a GUID or UPN and returns the corresponding user details
        including display name, GUID, and UPN for better readability in reports.

    .PARAMETER UserIdOrUpn
        The user identifier - either a GUID or user principal name (UPN)

    .EXAMPLE
        Resolve-UserIdentity -UserIdOrUpn "john.doe@contoso.com"

    .EXAMPLE
        Resolve-UserIdentity -UserIdOrUpn "846eca8a-95ce-4d54-a45c-37b5fea0e3a8"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserIdOrUpn
    )

    # Check if input is likely a GUID
    $guidPattern = "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"
    $isGuid = $UserIdOrUpn -match $guidPattern

    try {
        # Query Microsoft Graph for user details
        if ($isGuid) {
            # If we have a GUID, query directly by ID
            $user = Get-MgUser -UserId $UserIdOrUpn -ErrorAction Stop
        }
        else {
            # If we have a UPN or other identifier, filter by userPrincipalName
            $filter = "userPrincipalName eq '$UserIdOrUpn'"
            $user = Get-MgUser -Filter $filter -ErrorAction Stop

            # If not found by UPN, try searching by display name
            if (-not $user) {
                $filter = "displayName eq '$UserIdOrUpn'"
                $user = Get-MgUser -Filter $filter -ErrorAction Stop
            }
        }

        if ($user) {
            return [PSCustomObject]@{
                Id                = $user.Id
                UserPrincipalName = $user.UserPrincipalName
                DisplayName       = $user.DisplayName
                JobTitle          = $user.JobTitle
                Department        = $user.Department
                Success           = $true
            }
        }
        else {
            Write-Verbose "User not found: $UserIdOrUpn"
            return [PSCustomObject]@{
                Id                = $UserIdOrUpn
                UserPrincipalName = $UserIdOrUpn
                DisplayName       = "Unknown User"
                Success           = $false
            }
        }
    }
    catch {
        Write-Verbose "Error resolving user identity: $($_.Exception.Message)"
        return [PSCustomObject]@{
            Id                = $UserIdOrUpn
            UserPrincipalName = $UserIdOrUpn
            DisplayName       = "Unknown User"
            Success           = $false
            Error             = $_.Exception.Message
        }
    }
}
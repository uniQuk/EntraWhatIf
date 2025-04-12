# Conditional Access WhatIf PowerShell Module Structure

## Module Overview

The Conditional Access WhatIf PowerShell module simulates the evaluation of Microsoft Entra Conditional Access policies against hypothetical sign-in scenarios. This module helps administrators understand, test, and troubleshoot Conditional Access policies without affecting real users.

## Module Structure

```
whatifcli/
├── WhatIfCA.psd1             # Module manifest
├── WhatIfCA.psm1             # Module script file
├── Private/                  # Private helper functions
│   ├── Get-CAPolicy.ps1      # Functions to get policies from Microsoft Graph
│   ├── Resolve-CACondition.ps1  # Functions to evaluate policy conditions
│   ├── Resolve-CAGrantControl.ps1  # Functions to evaluate grant controls
│   ├── Resolve-CASessionControl.ps1  # Functions to evaluate session controls
│   └── Utils.ps1             # Utility functions
├── Public/                   # Exported functions
│   ├── Invoke-CAWhatIf.ps1   # Main function to simulate policy evaluation
│   ├── Get-CAWhatIfReport.ps1   # Generate a report of simulation results
│   ├── Get-CANamedLocation.ps1  # Get named locations for simulation
│   └── Get-CADisplayInfo.ps1    # Format results for display
└── Examples/                 # Example scripts
    ├── Simulate-GuestAccess.ps1
    ├── Simulate-AdminAccess.ps1
    └── Simulate-MobileDevice.ps1
```

## Core Functions

### Invoke-CAWhatIf

```powershell
function Invoke-CAWhatIf {
    [CmdletBinding()]
    param (
        # User parameters
        [Parameter()]
        [string]$UserId,
        
        [Parameter()]
        [string[]]$UserGroups,
        
        [Parameter()]
        [string[]]$UserRoles,
        
        [Parameter()]
        [ValidateSet('None', 'Low', 'Medium', 'High')]
        [string]$UserRiskLevel = 'None',
        
        # Resource parameters
        [Parameter()]
        [string]$AppId,
        
        [Parameter()]
        [string]$AppDisplayName,
        
        # Sign-in context
        [Parameter()]
        [string]$IpAddress,
        
        [Parameter()]
        [string]$Location,
        
        [Parameter()]
        [ValidateSet('Browser', 'MobileAppsAndDesktopClients', 'ExchangeActiveSync', 'Other')]
        [string]$ClientAppType = 'Browser',
        
        [Parameter()]
        [ValidateSet('Windows', 'iOS', 'Android', 'macOS', 'Linux', 'Other')]
        [string]$DevicePlatform,
        
        [Parameter()]
        [bool]$DeviceCompliant = $false,
        
        [Parameter()]
        [ValidateSet('AzureAD', 'Hybrid', 'Registered', 'Personal')]
        [string]$DeviceJoinType = 'Personal',
        
        [Parameter()]
        [ValidateSet('None', 'Low', 'Medium', 'High')]
        [string]$SignInRiskLevel = 'None',
        
        [Parameter()]
        [bool]$MfaAuthenticated = $false,
        
        [Parameter()]
        [bool]$ApprovedApplication = $false,
        
        [Parameter()]
        [bool]$AppProtectionPolicy = $false,
        
        [Parameter()]
        [bool]$BrowserPersistence = $false,
        
        # Filtering parameters
        [Parameter()]
        [string[]]$PolicyIds,
        
        [Parameter()]
        [switch]$IncludeReportOnly,
        
        # Output parameters
        [Parameter()]
        [ValidateSet('Basic', 'Detailed')]
        [string]$OutputLevel = 'Basic'
    )
    
    # Function implementation
}
```

### Get-CAWhatIfReport

```powershell
function Get-CAWhatIfReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$SimulationResults,
        
        [Parameter()]
        [ValidateSet('Text', 'HTML', 'JSON')]
        [string]$Format = 'Text',
        
        [Parameter()]
        [string]$OutputPath
    )
    
    # Function implementation
}
```

## Private Function Details

### Get-CAPolicy

```powershell
function Get-CAPolicy {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]$PolicyIds,
        
        [Parameter()]
        [switch]$IncludeReportOnly
    )
    
    # Implementation to query Microsoft Graph for policies
}
```

### Resolve-CACondition

```powershell
function Resolve-CACondition {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,
        
        [Parameter(Mandatory = $true)]
        [object]$UserContext,
        
        [Parameter(Mandatory = $true)]
        [object]$ResourceContext,
        
        [Parameter(Mandatory = $true)]
        [object]$DeviceContext,
        
        [Parameter(Mandatory = $true)]
        [object]$RiskContext,
        
        [Parameter(Mandatory = $true)]
        [object]$LocationContext
    )
    
    # Implementation to evaluate if policy conditions apply
}
```

### Resolve-CAGrantControl

```powershell
function Resolve-CAGrantControl {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,
        
        [Parameter(Mandatory = $true)]
        [object]$UserContext,
        
        [Parameter(Mandatory = $true)]
        [object]$DeviceContext
    )
    
    # Implementation to evaluate grant controls
}
```

### Resolve-CASessionControl

```powershell
function Resolve-CASessionControl {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy
    )
    
    # Implementation to evaluate session controls
}
```

## Data Models

### UserContext

```powershell
$UserContext = @{
    Id = $UserId
    MemberOf = $UserGroups
    DirectoryRoles = $UserRoles
    UserRiskLevel = $UserRiskLevel
    MfaAuthenticated = $MfaAuthenticated
}
```

### ResourceContext

```powershell
$ResourceContext = @{
    AppId = $AppId
    DisplayName = $AppDisplayName
    ClientAppType = $ClientAppType
    ApprovedApplication = $ApprovedApplication
}
```

### DeviceContext

```powershell
$DeviceContext = @{
    Platform = $DevicePlatform
    Compliance = $DeviceCompliant
    JoinType = $DeviceJoinType
    AppProtectionPolicy = $AppProtectionPolicy
    BrowserPersistence = $BrowserPersistence
}
```

### RiskContext

```powershell
$RiskContext = @{
    SignInRiskLevel = $SignInRiskLevel
    UserRiskLevel = $UserRiskLevel
}
```

### LocationContext

```powershell
$LocationContext = @{
    IpAddress = $IpAddress
    NamedLocation = $Location
}
```

## Results Format

```powershell
$PolicyEvaluationResult = @{
    PolicyId = $Policy.Id
    DisplayName = $Policy.DisplayName
    State = $Policy.State  # Enabled, Disabled, Report-only
    Applies = $true/false
    AccessResult = "Blocked"/"Granted"/"ConditionallyGranted"
    GrantControlsRequired = @()
    SessionControlsApplied = @()
    EvaluationDetails = @{
        UserInScope = $true/false
        ResourceInScope = $true/false
        NetworkInScope = $true/false
        ClientAppInScope = $true/false
        DevicePlatformInScope = $true/false
        DeviceStateInScope = $true/false
        RiskLevelsInScope = $true/false
    }
}
```

## Microsoft Graph Integration

The module will use Microsoft Graph API for:

1. Retrieving CA policies
2. Retrieving named location definitions
3. Retrieving group and user information
4. Retrieving application information

Authentication to Microsoft Graph will leverage the Microsoft.Graph.Authentication module, supporting:

- Interactive authentication
- Service principal authentication
- Managed identity authentication
- Access token authentication

## Error Handling

The module will implement robust error handling:

1. Connection errors to Microsoft Graph
2. Permission errors (insufficient privileges)
3. Invalid parameter validation
4. Policy configuration errors
5. Resource not found errors

## Visualization

For detailed analysis, the module will support:

1. Text-based output for PowerShell console
2. HTML report generation with color-coded results
3. JSON output for integration with other tools
4. Format-Table and Format-List custom formatters

## Usage Examples

```powershell
# Basic example
Invoke-CAWhatIf -UserId "john.doe@contoso.com" -AppId "Office365" -DevicePlatform "Windows"

# Detailed example with multiple parameters
Invoke-CAWhatIf -UserId "john.doe@contoso.com" `
    -UserGroups "Sales", "VPN Users" `
    -UserRoles "User" `
    -AppId "00000002-0000-0ff1-ce00-000000000000" `
    -AppDisplayName "Exchange Online" `
    -IpAddress "203.0.113.1" `
    -ClientAppType "Browser" `
    -DevicePlatform "Windows" `
    -DeviceCompliant $true `
    -DeviceJoinType "AzureAD" `
    -SignInRiskLevel "Low" `
    -MfaAuthenticated $false `
    -OutputLevel "Detailed"

# Generate an HTML report
$results = Invoke-CAWhatIf -UserId "admin@contoso.com" -UserRoles "GlobalAdministrator" -AppId "Office365"
Get-CAWhatIfReport -SimulationResults $results -Format "HTML" -OutputPath "C:\Reports\CA-WhatIf-Report.html"
``` 
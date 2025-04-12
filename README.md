# WhatIfCA PowerShell Module

A PowerShell module to simulate Microsoft Entra Conditional Access policy evaluation for hypothetical sign-in scenarios. This tool helps administrators understand, test, and troubleshoot Conditional Access policies without affecting real users.

## Features

- Simulate how Conditional Access policies would evaluate against custom sign-in scenarios
- Support for all major Conditional Access conditions:
  - Users and groups
  - Cloud applications
  - Locations and networks
  - Client applications
  - Device platforms
  - Device state and compliance
  - Risk levels
- Evaluate policy grant controls (block, require MFA, etc.)
- Evaluate policy session controls
- Generate detailed reports in Text, HTML, or JSON formats

## Prerequisites

- PowerShell 7.x or higher
- Microsoft.Graph.Authentication module
- Microsoft.Graph.Identity.SignIns module
- Entra ID permissions:
  - Policy.Read.All
  - Directory.Read.All

## Installation

Clone this repository:

```powershell
git clone https://github.com/your-username/whatifpwsh.git
cd whatifpwsh
```

Import the module:

```powershell
Import-Module .\whatifcli\WhatIfCA.psd1
```

## Usage

### Basic Simulation

```powershell
Invoke-CAWhatIf -UserId "john.doe@contoso.com" -AppId "Office365" -DevicePlatform "Windows"
```

### Tabular Console Output

```powershell
Invoke-CAWhatIf -UserId "john.doe@contoso.com" -AppId "Office365" -DevicePlatform "Windows" -OutputLevel "Table"
```

### Detailed Simulation

```powershell
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
```

### Generate Reports

```powershell
# Generate a text report
$results = Invoke-CAWhatIf -UserId "john.doe@contoso.com" -AppId "Office365"
Get-CAWhatIfReport -SimulationResults $results -Format "Text"

# Generate an HTML report and save to file
Get-CAWhatIfReport -SimulationResults $results -Format "HTML" -OutputPath "C:\Reports\CA-WhatIf-Report.html"

# Generate a JSON report for integration with other tools
Get-CAWhatIfReport -SimulationResults $results -Format "JSON" -OutputPath "C:\Reports\CA-WhatIf-Report.json"
```

## Documentation

For more detailed documentation, see the [docs](./docs) directory, which includes:

- [Conditional Access Policies Overview](docs/ConditionalAccessPolicies.md)
- [Conditional Access Logical Rules](docs/ConditionalAccessLogicalRules.md)
- [WhatIfCA Module Structure](docs/ConditionalAccessWhatIfModule.md)

## How It Works

The WhatIfCA module:

1. Retrieves Conditional Access policies from your Entra ID tenant
2. Simulates how these policies would apply to the specified sign-in scenario
3. Evaluates the conditions of each policy to determine if it applies
4. For applicable policies, evaluates grant controls to determine access
5. For granted access, evaluates session controls
6. Combines the results to determine the final outcome
7. Generates a comprehensive report of the simulation

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

# WhatIf CLI for Microsoft Entra Conditional Access

A PowerShell module that simulates Microsoft Entra Conditional Access policy evaluation for hypothetical sign-in scenarios. This tool helps administrators and security teams test, validate, and understand how conditional access policies would apply to users in various scenarios before implementing them in production.

## Overview

WhatIf CLI for Conditional Access ("whatifcli") allows you to answer questions like:

- "What would happen if this user tried to access this application?"
- "Which policies would apply if a guest accessed our portal?"
- "Is our new MFA policy going to affect the expected users?"
- "Would this policy block access from a specific location or device?"

Unlike testing in production, whatifcli lets you simulate sign-in scenarios to understand policy impact ahead of time without affecting real users.

## Features

- **Policy Simulation**: Evaluate how conditional access policies would apply to hypothetical sign-in scenarios
- **Comprehensive Condition Support**: Test against all conditional access conditions including user, application, device, location, risk, and more
- **Guest User Support**: Simulate how policies apply to guest and external users
- **Detailed Output**: Get clear, detailed information about which policies apply, why, and what requirements they would impose
- **Offline Evaluation**: Test policy changes without implementing them in production
- **Multiple Output Formats**: View results as tables, detailed reports, or JSON for further processing
- **Microsoft-Compatible Logic**: Uses the same evaluation logic as Microsoft's native implementation

## Installation

### PowerShell Gallery (Recommended)

```powershell
# Install the module from PowerShell Gallery
Install-Module -Name EntraCAWhatIf -Scope CurrentUser

# Import the module
Import-Module EntraCAWhatIf
```

### Manual Installation

```powershell
# Clone the repository
git clone https://github.com/uniQuk/whatifcli.git

# Navigate to the directory and import the module
cd whatifcli
Import-Module ./whatifcli.psd1
```

## Prerequisites

- **PowerShell**: PowerShell 7 or higher
- **Microsoft Graph PowerShell SDK**:

  - Microsoft.Graph.Authentication
  - Microsoft.Graph.Identity.SignIns

- **Required Microsoft Graph Permissions**:
  - Policy.Read.All (to read conditional access policies)
  - Directory.Read.All (to read user and group information)
  - User.Read.All (to resolve user identities)
  - Group.Read.All (to evaluate group memberships)

## Basic Usage

### Evaluate All Policies for a User

```powershell
# Connect to Microsoft Graph first
Connect-MgGraph -Scopes "Policy.Read.All","Directory.Read.All","User.Read.All","Group.Read.All"

# Evaluate all policies for a user
Invoke-CAWhatIf -UserId "john.doe@contoso.com"
```

### Evaluate Access to a Specific Application

```powershell
Invoke-CAWhatIf -UserId "john.doe@contoso.com" -AppId "Office365"
```

### Simulate Access with Device Information

```powershell
Invoke-CAWhatIf -UserId "john.doe@contoso.com" -AppId "Office365" `
                -DevicePlatform "Windows" -DeviceCompliant $true -DeviceJoinType "AzureAD"
```

### Simulate Guest User Access

```powershell
Invoke-CAWhatIf -UserId "guest@partner.com" -AppId "SharePoint"
```

### Test from Different Network Locations

```powershell
# Test access from a specific IP address
Invoke-CAWhatIf -UserId "john.doe@contoso.com" -AppId "Office365" -IpAddress "203.0.113.1"

# Test access from a specific named location
Invoke-CAWhatIf -UserId "john.doe@contoso.com" -AppId "Office365" -Location "Trusted-Locations"

# Test access from a specific country (using ISO 2-character country code)
Invoke-CAWhatIf -UserId "john.doe@contoso.com" -AppId "Office365" -CountryCode "US"

# Test using both IP address and country code
Invoke-CAWhatIf -UserId "john.doe@contoso.com" -AppId "Office365" -IpAddress "203.0.113.1" -CountryCode "GB"
```

### Generate Detailed Reports

```powershell
# Get a detailed report of policy evaluation
Invoke-CAWhatIf -UserId "john.doe@contoso.com" -AppId "Office365" -OutputLevel "Detailed"

# Export results to JSON
Invoke-CAWhatIf -UserId "john.doe@contoso.com" -AppId "Office365" -OutputLevel "MicrosoftFormat" -AsJson
```

### Enable Diagnostic Output

```powershell
# Enable verbose diagnostic information (cross-platform example)
Invoke-CAWhatIf -UserId "john.doe@contoso.com" -Diagnostic -DiagnosticLogPath "/Users/youruser/diagnostic.log"
```

## Advanced Usage

### Evaluate Specific Policies

```powershell
# Only evaluate specific policies by ID
Invoke-CAWhatIf -UserId "john.doe@contoso.com" -AppId "Office365" -PolicyIds "policy-guid-1","policy-guid-2"
```

### Simulate Risk Conditions

```powershell
# Simulate a sign-in with high risk
Invoke-CAWhatIf -UserId "john.doe@contoso.com" -AppId "Office365" -SignInRiskLevel "High"
```

## Parameter Reference

| Parameter            | Description                                               |
| -------------------- | --------------------------------------------------------- |
| `UserId`             | User object ID or UPN to simulate                         |
| `ServicePrincipalId` | Service principal ID to simulate                          |
| `UserGroups`         | Groups the user is a member of                            |
| `UserRoles`          | Directory roles assigned to the user                      |
| `AppId`              | Application ID to simulate access to                      |
| `AppDisplayName`     | Display name of the application                           |
| `UserAction`         | User action to simulate (e.g., registering security info) |
| `IpAddress`          | IP address for the sign-in                                |
| `Location`           | Named location for the sign-in                            |
| `CountryCode`        | Two-character ISO country code (e.g., "US", "GB", "DE")   |
| `ClientAppType`      | Client application type                                   |
| `DevicePlatform`     | Device platform (Windows, iOS, Android, etc.)             |
| `DeviceCompliant`    | Whether the device is compliant                           |
| `DeviceJoinType`     | Device join type (AzureAD, Hybrid, etc.)                  |
| `SignInRiskLevel`    | Sign-in risk level                                        |
| `UserRiskLevel`      | User risk level                                           |
| `PolicyIds`          | Specific policy IDs to evaluate                           |
| `OutputLevel`        | Level of detail in the output                             |
| `Diagnostic`         | Enable diagnostic output                                  |

> **Note:** Not all parameters are required. Some are mutually exclusive (e.g., `UserId` vs `ServicePrincipalId`).

## Examples of Output

### Table Format (Default)

```
Policy Name                                Action    Applies   Controls              Reason
-----------                                ------    -------   --------              ------
MFA for All Users                          Report    Yes       U✓ A✓ P✓ N✓         Requires MFA
Block Legacy Authentication                Enforce   No        U✓ A✗ P✓ N✓         Client app type not in scope
Guest Access - Require MFA                 Enforce   No        U✗ A✓ P✓ N✓         User is not a guest
```

> **Note:** Output formatting is for illustration purposes.

### Detailed Output

```
EVALUATION SUMMARY
-----------------
User: john.doe@contoso.com
Application: Office365
Access: ALLOWED
Required Controls: MFA

DETAILED RESULTS
--------------
Policy: MFA for All Users
  State: Enabled
  Applies: Yes
  Access Result: ConditionallyGranted
  Required Controls: MFA
  Reasons: User is included by default, all applications included
```

## Contributing

Contributions to whatifcli are welcome and appreciated! Here's how you can contribute:

1. **Report Bugs**: If you find a bug, please [open an issue](https://github.com/uniQuk/whatifcli/issues) with details on how to reproduce it
2. **Suggest Features**: Have an idea? [Open an issue](https://github.com/uniQuk/whatifcli/issues) to suggest new features
3. **Submit Pull Requests**: Implement new features or fix bugs and submit a PR
4. **Improve Documentation**: Help improve the documentation with clear examples and explanations

Please ensure your code follows the project's style and includes appropriate tests.

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

## Acknowledgments

- [Microsoft Graph API documentation](https://learn.microsoft.com/graph/api/resources/conditionalaccessroot?view=graph-rest-beta) and team
- PowerShell community
- All contributors to this project

# Conditional Access Policies

## Overview

A Conditional Access policy is an if-then statement of **Assignments** and **Access controls**. Conditional Access brings signals together to make decisions and enforce organizational policies. The formula for a Conditional Access policy is:

**IF** (assignments) **THEN** (access controls)

## Policy Components

### 1. Assignments

Assignments control the who, what, and where of the Conditional Access policy:

#### 1.1 Users and Groups
- **Include**: All users, specific groups, directory roles, or external guest users
- **Exclude**: Specific users or groups that should be exempted

#### 1.2 Target Resources
- **Include/Exclude**: Cloud applications, user actions, or authentication contexts
- Can target specific applications or all applications

#### 1.3 Network
- IP addresses, geographies, and Global Secure Access' compliant networks
- Trusted locations vs. untrusted locations

#### 1.4 Conditions
- **Sign-in Risk**: Risk levels from Microsoft Entra ID Protection
- **Device Platforms**: Windows, iOS, Android, macOS, Linux
- **Client Apps**: Browser, mobile apps, desktop clients
- **Filter for Devices**: Target specific devices based on attributes

### 2. Access Controls

Access controls determine how a policy is enforced:

#### 2.1 Grant Controls
- **Block Access**: Denies access based on assignments
- **Grant Access**: Requires one or more of the following:
  - Multifactor authentication (MFA)
  - Device compliance (Intune)
  - Microsoft Entra hybrid joined device
  - Approved client app
  - App protection policy
  - Password change
  - Terms of use

  Administrators can choose:
  - Require ALL selected controls (AND logic)
  - Require ONE of the selected controls (OR logic)

#### 2.2 Session Controls
- **App Enforced Restrictions**: Works with Exchange Online and SharePoint Online
- **Conditional Access App Control**: Uses Microsoft Defender for Cloud Apps
- **Sign-in Frequency**: Customizes authentication frequency
- **Persistent Browser Session**: Allows users to remain signed in
- **Customize Continuous Access Evaluation**
- **Disable Resilience Defaults**

## Policy Evaluation

Conditional Access policies are enforced in two phases:

### Phase 1: Session Detail Collection
- Gather session information (network location, device identity)
- This phase applies to both enabled policies and policies in report-only mode

### Phase 2: Enforcement
1. Use session details to identify unmet requirements
2. Block access if a policy is configured with block grant control
3. Prompt for additional requirements in this order:
   1. Multifactor authentication
   2. Device compliance
   3. Microsoft Entra hybrid joined device
   4. Approved client app
   5. App protection policy
   6. Password change
   7. Terms of use
   8. Custom controls
4. Apply session controls (App enforced, Microsoft Defender for Cloud Apps, token lifetime)

## Policy Interaction

- Multiple policies can apply to a user simultaneously
- All applicable policies must be satisfied
- All assignments are logically ANDed - all must be satisfied to trigger a policy
- For "Require one of the selected controls" option, the system prompts in defined order

## Minimum Requirements for a Policy

A Conditional Access policy must contain at minimum:
- **Name** of the policy
- **Assignments**
  - Users and/or groups
  - Cloud apps or actions
- **Access controls**
  - Grant or Block controls

## Common Conditional Access Approaches

### Zero Trust Framework Approach
Policies can be organized by user personas:
- Internal users (Base protection, identity protection)
- Guest users
- Workload identities

### Security Levels Approach
- Basic protection for all users
- Sensitive data/app protection
- Privileged account protection

## What-If Tool

The What-If tool allows administrators to test and understand how Conditional Access policies would affect a hypothetical sign-in scenario. It helps:
- Test new policies before enabling
- Troubleshoot existing policies
- Plan policy changes
- Understand policy interactions

## PowerShell Support

Conditional Access policies can be managed programmatically using:
- Microsoft Graph API
- PowerShell modules (Microsoft.Graph, AzureADPreview) 
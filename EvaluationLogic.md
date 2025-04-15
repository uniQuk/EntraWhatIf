# Conditional Access Policy Evaluation Logic

This document describes, in detail, the evaluation flow for a Conditional Access (CA) policy as implemented in the `Invoke-CAWhatIf` module.

---

## 1. Input Gathering
- **User Context:** UserId, UserGroups, UserRoles, Guest status, etc.
- **Resource Context:** AppId, ClientAppType, Resource details.
- **Device Context:** DevicePlatform, DeviceCompliant, DeviceJoinType, etc.
- **Location Context:** IP Address, CountryCode, NamedLocationId, TrustedLocation.
- **Risk Context:** UserRiskLevel, SignInRiskLevel.
- **Other:** AuthenticationContext, MFA status, etc.

## 2. Policy Loading
- All policies are loaded using `Get-CAPolicy`.
- If `PolicyIds` are specified, only those are loaded.
- Optionally includes report-only policies.

## 3. Per-Policy Evaluation Loop
For each policy:

### a. Initial State
- Result object is initialized with all condition flags set to `false`.

### b. Applicability Checks (Scope)
- **User Scope:** Is the user included/excluded?
- **Resource Scope:** Is the app/resource in scope?
- **Early Exit:** If user or resource is not in scope, policy does not apply.

### c. Condition Evaluation (If in scope)
- **Network/Location:** Is the sign-in from an included/excluded location?
- **Client App:** Is the client app type in scope?
- **Device Platform:** Is the device platform in scope?
- **Device State:** Is the device compliant/registered as required?
- **Risk Levels:** Are user/sign-in risk levels in scope?
- **Authentication Context:** Is the required context present?
- Each condition is evaluated using dedicated functions (e.g., `Test-NetworkInScope`, `Test-DeviceFilter`).
- **Short-circuit:** If any required condition is not met, policy does not apply.

### d. Grant & Session Controls (If all conditions met)
- **Grant Controls:** Evaluated using `Resolve-CAGrantControl`.
  - If all required controls are satisfied, access is granted.
  - If only some are satisfied, access is conditionally granted.
  - If not satisfied, access is blocked.
- **Session Controls:** Evaluated using `Resolve-CASessionControl` if access is granted/conditional.

### e. Result Recording
- The result object is updated with:
  - `Applies` (true/false)
  - `AccessResult` (Granted, Blocked, ConditionallyGranted)
  - `GrantControlsRequired`, `SessionControlsApplied`
  - Detailed evaluation flags for each condition
  - Reasons for each decision

### f. Diagnostics (Optional)
- If `-Diagnostic` is enabled, detailed logs are written for each evaluation stage using `Write-DiagnosticOutput`.

---

## 4. Aggregation & Output
- All policy results are aggregated.
- Overall access decision is determined (allowed/blocked/conditional).
- Results can be formatted for Microsoft compatibility (`Format-MicrosoftCAWhatIfResponse`).
- Reports can be generated using `Get-CAWhatIfReport`.

---

## 5. Special Notes
- **Optimizations:** Some conditions (e.g., network) have optimized evaluation paths for performance and accuracy.
- **Extensibility:** The evaluation logic is modular, allowing for future condition types or grant controls.
- **Diagnostics:** Diagnostic output is highly granular for troubleshooting and auditing.

---

## 6. Visual Flow (Simplified)

```
[Input Gathering]
      |
[Load Policies]
      |
[For Each Policy]
      |
[User/Resource Scope?] --No--> [Skip]
      |
[All Conditions Met?] --No--> [Skip]
      |
[Grant/Session Controls]
      |
[Record Result]
      |
[Aggregate Results]
      |
[Output/Report]
```

---

For further details, see the in-code documentation in `Invoke-CAWhatIf.ps1` and related private functions.

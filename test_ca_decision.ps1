Start-Transcript -Path "./out.log" -Append
# Test script to verify Conditional Access evaluation with and without diagnostic mode
# Load the module
Import-Module ./whatifcli/whatifcli.psd1 -Force

Write-Host "Testing CA evaluation for user 'awsm@n7.uk'" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# Test user for CA02 policy (which has "All" users)
$testUser = "awsm@n7.uk"

# Enable verbose output
$VerbosePreference = "Continue"

# First, test with normal mode
Write-Host "Testing CA02 policy without -Diagnostic flag" -ForegroundColor Cyan
$resultNormal = Invoke-CAWhatIf -UserId $testUser

# Then test with diagnostic mode
Write-Host "`nTesting CA02 policy with -Diagnostic flag" -ForegroundColor Cyan
$resultDiagnostic = Invoke-CAWhatIf -UserId $testUser -Diagnostic

# Add a clear section for the enhanced tracing test
Write-Host "`n===== ENHANCED TRACING TEST =====" -ForegroundColor Cyan
Write-Host "Testing with enhanced path tracing" -ForegroundColor Yellow
$resultWithTracing = Invoke-CAWhatIf -UserId $testUser -Diagnostic

# Check for the specific CA02 policy
$ca02Normal = $resultNormal | Where-Object { $_.PolicyName -like "*CA02*" }
$ca02Diagnostic = $resultDiagnostic | Where-Object { $_.PolicyName -like "*CA02*" }

Write-Host "`n=== CA02 Policy Comparison ===" -ForegroundColor Yellow
Write-Host "Normal mode: $($ca02Normal.PolicyName)" -ForegroundColor Green
Write-Host "  Applies: $($ca02Normal.Applies)" -ForegroundColor Green
Write-Host "  Reason: $($ca02Normal.Reason)" -ForegroundColor Green
Write-Host "`nDiagnostic mode: $($ca02Diagnostic.PolicyName)" -ForegroundColor Magenta
Write-Host "  Applies: $($ca02Diagnostic.Applies)" -ForegroundColor Magenta
Write-Host "  Reason: $($ca02Diagnostic.Reason)" -ForegroundColor Magenta

# Directly analyze the CA02 policy file
Write-Host "`n=== Direct CA02 Policy Analysis ===" -ForegroundColor Yellow
$policyPath = "./z_no_upload/policies/original/CA02 - Require MFA for all users.json"
$policy = Get-Content $policyPath -Raw | ConvertFrom-Json

Write-Host "Policy Name: $($policy.DisplayName)" -ForegroundColor Cyan
Write-Host "User Conditions:" -ForegroundColor Cyan
Write-Host "  Include Users: $($policy.Conditions.Users.IncludeUsers -join ', ')" -ForegroundColor Cyan
Write-Host "  Exclude Users: $($policy.Conditions.Users.ExcludeUsers -join ', ')" -ForegroundColor Cyan

# Check if the test user is actually excluded
Write-Host "`nChecking if user '$testUser' is excluded:" -ForegroundColor Yellow

# Manually create a user context for testing
$userContext = @{
    Id  = $null  # This would be resolved from Graph in real scenarios
    UPN = $testUser
}

# Try to resolve the user if the module is loaded correctly
try {
    $resolvedUser = Resolve-UserIdentity -UserIdOrUpn $testUser
    if ($resolvedUser.Success) {
        $userContext.Id = $resolvedUser.Id
        $userContext.UPN = $resolvedUser.UserPrincipalName

        Write-Host "User ID: $($userContext.Id)" -ForegroundColor Cyan
        Write-Host "User UPN: $($userContext.UPN)" -ForegroundColor Cyan
    }
}
catch {
    Write-Warning "Could not resolve user: $_"
    Write-Host "User ID: Unknown (using UPN as fallback)" -ForegroundColor Yellow
    Write-Host "User UPN: $($userContext.UPN)" -ForegroundColor Cyan
}

# Check if the user's ID is in the excluded users list
$isExcluded = $false
$excludedUsers = $policy.Conditions.Users.ExcludeUsers
if ($excludedUsers) {
    foreach ($excludedUser in $excludedUsers) {
        # Safely handle null ID values
        $userIdLower = if ($userContext.Id) { $userContext.Id.ToLower() } else { "" }
        $userUpnLower = $userContext.UPN.ToLower()
        $excludedUserLower = $excludedUser.ToLower()

        if ($userIdLower -eq $excludedUserLower -or $userUpnLower -eq $excludedUserLower) {
            $isExcluded = $true
            $matchType = if ($userIdLower -eq $excludedUserLower) { "ID" } else { "UPN" }
            Write-Host "User is EXCLUDED from policy by $matchType match!" -ForegroundColor Red
            Write-Host "  Excluded User: $excludedUser" -ForegroundColor Red
            Write-Host "  User $($matchType): $(if ($matchType -eq 'ID') { $userContext.Id } else { $userContext.UPN })" -ForegroundColor Red
            break
        }
    }
}

if (-not $isExcluded) {
    Write-Host "User is NOT excluded from policy." -ForegroundColor Green
}

# Test the user scope determination directly - only if the function is available
Write-Host "`n=== Direct User Scope Test ===" -ForegroundColor Yellow
$scopeResult = $null
try {
    # This function might not be directly accessible - it's an internal function in the module
    $scopeResult = Test-UserInScope -Policy $policy -UserContext $userContext
    Write-Host "User in scope: $($scopeResult.InScope)" -ForegroundColor $(if ($scopeResult.InScope) { "Green" } else { "Red" })
    Write-Host "Reason: $($scopeResult.Reason)" -ForegroundColor Cyan
    Write-Host "Decision Path: $($scopeResult.Path)" -ForegroundColor Cyan

    # Show detailed trace if available in the enhanced version
    if ($scopeResult.Trace) {
        Write-Host "`nDetailed Trace:" -ForegroundColor Magenta
        foreach ($step in $scopeResult.Trace) {
            Write-Host "  $step" -ForegroundColor White
        }
    }
}
catch {
    Write-Warning "Could not directly test user scope: $_"
    Write-Host "This is expected if the internal function is not accessible" -ForegroundColor Yellow
}

# Compare the results
Write-Host "`nResults Comparison:" -ForegroundColor Cyan
Write-Host "===================" -ForegroundColor Cyan

Write-Host "Without Diagnostic: Access Allowed = $($resultNormal.AccessAllowed)" -ForegroundColor $(if ($resultNormal.AccessAllowed) { "Green" } else { "Red" })
Write-Host "With Diagnostic:    Access Allowed = $($resultDiagnostic.AccessAllowed)" -ForegroundColor $(if ($resultDiagnostic.AccessAllowed) { "Green" } else { "Red" })

$match = $resultNormal.AccessAllowed -eq $resultDiagnostic.AccessAllowed
Write-Host "`nResults match: $match" -ForegroundColor $(if ($match) { "Green" } else { "Red" })

# Add detailed diagnostic for CA02 policy specifically
Write-Host "`nDetailed diagnostic for CA02 policy:" -ForegroundColor Cyan
$ca02Standard = $resultNormal.DetailedResults | Where-Object { $_.DisplayName -like "*CA02*" }
$ca02Diagnostic = $resultDiagnostic.DetailedResults | Where-Object { $_.DisplayName -like "*CA02*" }

if ($ca02Standard -and $ca02Diagnostic) {
    Write-Host "  Standard evaluation:" -ForegroundColor Yellow
    Write-Host "    Applies: $($ca02Standard.Applies)"
    Write-Host "    User in scope: $($ca02Standard.EvaluationDetails.UserInScope)"

    if ($ca02Standard.EvaluationDetails.Reasons -and $ca02Standard.EvaluationDetails.Reasons.User) {
        Write-Host "    User scope reason: $($ca02Standard.EvaluationDetails.Reasons.User.Reason)"
        Write-Host "    Decision path: $($ca02Standard.EvaluationDetails.Reasons.User.Path)"
    }

    Write-Host "  Diagnostic evaluation:" -ForegroundColor Yellow
    Write-Host "    Applies: $($ca02Diagnostic.Applies)"
    Write-Host "    User in scope: $($ca02Diagnostic.EvaluationDetails.UserInScope)"

    if ($ca02Diagnostic.EvaluationDetails.Reasons -and $ca02Diagnostic.EvaluationDetails.Reasons.User) {
        Write-Host "    User scope reason: $($ca02Diagnostic.EvaluationDetails.Reasons.User.Reason)"
        Write-Host "    Decision path: $($ca02Diagnostic.EvaluationDetails.Reasons.User.Path)"
    }
}

# Now let's examine the actual JSON policy directly to understand the issue
Write-Host "`nExamining CA02 policy directly:" -ForegroundColor Cyan
$policyFilePath = "./z_no_upload/policies/original/CA02 - Require MFA for all users.json"

# Read the policy file if it exists
if (Test-Path $policyFilePath) {
    $policy = Get-Content -Path $policyFilePath | ConvertFrom-Json

    Write-Host "  Policy has the following user conditions:" -ForegroundColor Yellow
    Write-Host "    Include users: $($policy.conditions.users.includeUsers -join ', ')"
    Write-Host "    Exclude users: $($policy.conditions.users.excludeUsers -join ', ')"

    # Check if user is in excluded list
    $userIdOrUpn = "awsm@n7.uk"
    $excludedUsers = $policy.conditions.users.excludeUsers

    # Check user resolution
    Write-Host "`n  Testing user resolution and trace details:"  -ForegroundColor Yellow
    Write-Host "  ----------------------------------------"  -ForegroundColor Yellow

    try {
        # Try to resolve the user identity
        Write-Host "  Resolving user: $userIdOrUpn" -ForegroundColor Cyan

        # Use the module's Resolve-UserIdentity function if available
        if (Get-Command "Resolve-UserIdentity" -ErrorAction SilentlyContinue) {
            $resolvedUser = Resolve-UserIdentity -UserIdOrUpn $userIdOrUpn

            if ($resolvedUser.Success) {
                Write-Host "  User resolved to: $($resolvedUser.Id) (UPN: $($resolvedUser.UserPrincipalName))" -ForegroundColor Green
                Write-Host "  ID lowercase: $($resolvedUser.Id.ToLower())" -ForegroundColor Green

                # Manually check exclusions
                Write-Host "`n  Manual exclusion check:" -ForegroundColor Magenta
                foreach ($excludedUser in $excludedUsers) {
                    $excludedUserLower = $excludedUser.ToLower()
                    $userIdLower = $resolvedUser.Id.ToLower()
                    $userUpnLower = $resolvedUser.UserPrincipalName.ToLower()

                    $isExcludedById = ($userIdLower -eq $excludedUserLower)
                    $isExcludedByUpn = ($userUpnLower -eq $excludedUserLower)
                    $isExcluded = $isExcludedById -or $isExcludedByUpn

                    Write-Host "    Checking against excluded user: $excludedUser" -ForegroundColor Cyan
                    Write-Host "      User ID match: $isExcludedById" -ForegroundColor $(if ($isExcludedById) { "Red" } else { "Green" })
                    Write-Host "      User UPN match: $isExcludedByUpn" -ForegroundColor $(if ($isExcludedByUpn) { "Red" } else { "Green" })
                    Write-Host "      Overall excluded: $isExcluded" -ForegroundColor $(if ($isExcluded) { "Red" } else { "Green" })
                }
            }
            else {
                Write-Host "  Failed to resolve user." -ForegroundColor Red
            }
        }
        else {
            Write-Host "  Resolve-UserIdentity function not available." -ForegroundColor Red
            Write-Host "  This is expected when running the script independently." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  Error in user resolution: $_" -ForegroundColor Red
    }
}

if (-not $match) {
    Write-Host "`nInvestigating differences..." -ForegroundColor Yellow

    # Compare applicable policies
    $standardApplicable = $resultNormal.DetailedResults | Where-Object { $_.Applies -eq $true }
    $diagnosticApplicable = $resultDiagnostic.DetailedResults | Where-Object { $_.Applies -eq $true }

    Write-Host "`nApplicable Policies:" -ForegroundColor Cyan
    Write-Host "Without Diagnostic: $($standardApplicable.Count) policies apply" -ForegroundColor White
    Write-Host "With Diagnostic:    $($diagnosticApplicable.Count) policies apply" -ForegroundColor White

    # Show decision paths for policies that differ
    Write-Host "`nPolicies with different evaluation:" -ForegroundColor Cyan
    foreach ($policy in $resultNormal.DetailedResults) {
        $diagnosticPolicy = $resultDiagnostic.DetailedResults | Where-Object { $_.PolicyId -eq $policy.PolicyId }
        if ($policy.Applies -ne $diagnosticPolicy.Applies) {
            Write-Host "  Policy: $($policy.DisplayName)" -ForegroundColor Yellow
            Write-Host "    Without Diagnostic: Applies = $($policy.Applies)" -ForegroundColor $(if ($policy.Applies) { "Green" } else { "Red" })
            Write-Host "    With Diagnostic:    Applies = $($diagnosticPolicy.Applies)" -ForegroundColor $(if ($diagnosticPolicy.Applies) { "Green" } else { "Red" })

            # Show decision path if available
            if ($policy.DecisionPath) {
                Write-Host "    Decision Path (without diagnostic): $($policy.DecisionPath)" -ForegroundColor White
            }
            if ($diagnosticPolicy.DecisionPath) {
                Write-Host "    Decision Path (with diagnostic): $($diagnosticPolicy.DecisionPath)" -ForegroundColor White
            }
        }
    }
}
else {
    Write-Host "`nFix was successful! Evaluation is now consistent with or without diagnostic mode." -ForegroundColor Green
}

Write-Host "`nDone." -ForegroundColor Cyan
Stop-Transcript
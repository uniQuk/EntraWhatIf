# Script to extract excluded user GUIDs from a CA policy

$policyFilePath = "./z_no_upload/policies/original/CA02 - Require MFA for all users.json"

# Read the policy file
$policy = Get-Content -Path $policyFilePath | ConvertFrom-Json

# Get the excluded users
$excludedUsers = $policy.conditions.users.excludeUsers

# Output the result
Write-Host "Excluded users in policy 'CA02 - Require MFA for all users':"
$excludedUsers | ForEach-Object {
    Write-Host "  $_"
}

Write-Host "`nTo check if a user would be affected, convert their UPN to a GUID using:"
Write-Host "Get-MgUser -Filter `"userPrincipalName eq 'user@example.com'`" | Select-Object -Property Id"
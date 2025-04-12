# Standalone Invoke-CAWhatIf function
# Load the Microsoft Graph module
Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction SilentlyContinue

# Source the required functions
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
. "$scriptPath/whatifcli/Private/Resolve-UserIdentity.ps1"
. "$scriptPath/whatifcli/Private/Resolve-GroupMembership.ps1"
. "$scriptPath/whatifcli/Private/Get-CAPolicy.ps1"
. "$scriptPath/whatifcli/Private/Resolve-CACondition.ps1"
. "$scriptPath/whatifcli/Private/Resolve-CAGrantControl.ps1"
. "$scriptPath/whatifcli/Private/Resolve-CASessionControl.ps1"
. "$scriptPath/whatifcli/Public/Invoke-CAWhatIf.ps1"

# Now call the function
Invoke-CAWhatIf -UserId "awsm@n7.uk" -Diagnostic
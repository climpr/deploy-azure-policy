#Requires -Modules @{ ModuleName="Az.Accounts"; ModuleVersion="3.0.0" }
#Requires -Modules @{ ModuleName="Az.ResourceGraph"; ModuleVersion="1.0.0" }
#Requires -Modules @{ ModuleName="Az.Resources"; ModuleVersion="7.1.0" }

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [ValidateScript({ $_ | Test-Path -PathType Container })]
    [string]
    $Path,
    
    [Parameter(Mandatory = $false)]
    [array]
    $FilesToInclude,

    [Parameter(Mandatory = $false)]
    [string]
    $Pattern,

    [Parameter(Mandatory = $false)]
    [bool]
    $Cleanup
)

Write-Debug "Set-AzurePolicy.ps1: Started"
Write-Debug "Input parameters: $($PSBoundParameters | ConvertTo-Json -Depth 3)"

#* Establish defaults
$scriptRoot = $PSScriptRoot
Write-Debug "Working directory: $((Resolve-Path -Path .).Path)"
Write-Debug "Script root directory: $(Resolve-Path -Relative -Path $scriptRoot)"

#* Parse climprconfig.json
$climprConfigPath = (Test-Path -Path "$Path/climprconfig.json") ? "$Path/climprconfig.json" : "climprconfig.json"
$climprConfig = Get-Content -Path $climprConfigPath | ConvertFrom-Json -AsHashtable -Depth 10 -NoEnumerate
$defaultLocation = $climprConfig.policyManagement.defaultLocation
$rootManagementGroupId = $climprConfig.policyManagement.rootManagementGroupId
$maxExemptionExpirationDateInDays = $climprConfig.policyManagement.maxExemptionExpirationDateInDays
$ignoredPolicyCreatorIdentities = $climprConfig.policyManagement.ignoredPolicyCreatorIdentities

#* Import modules
Import-Module $scriptRoot/PolMan.psm1 -Force

#* Get exclusions principal IDs
try {
    foreach ($identityDefinition in $ignoredPolicyCreatorIdentities) {
        $identityDefinition.principalId = $identityDefinition.principalId ?? (Get-AzADServicePrincipal -DisplayName $identityDefinition.displayName -ErrorAction "Stop").Id
    }
}
catch {
    Write-Error `
        -Exception "Insufficient permissions" `
        -Message "Identity requires the Directory Reader role assignment in Entra Id."
}

#* Get files to process
$policyFiles = Get-PolManPolicyFile -Path $Path -Type Policy -Pattern $Pattern -FilesToInclude $FilesToInclude
$initiativeFiles = Get-PolManPolicyFile -Path $Path -Type Initiative -Pattern $Pattern -FilesToInclude $FilesToInclude
$policyAssignmentFiles = Get-PolManPolicyFile -Path $Path -Type PolicyAssignment -Pattern $Pattern -FilesToInclude $FilesToInclude
$initiativeAssignmentFiles = Get-PolManPolicyFile -Path $Path -Type InitiativeAssignment -Pattern $Pattern -FilesToInclude $FilesToInclude
$exemptionFiles = Get-PolManPolicyFile -Path $Path -Type Exemption -Pattern $Pattern -FilesToInclude $FilesToInclude

#* Process objects
$defaultScope = "/providers/Microsoft.Management/managementGroups/$rootManagementGroupId"

#* Policies
Write-Output "::group::Processing Policy Deployments"

$policyRequests = $policyFiles | Set-PolManPolicy -DefaultScope $defaultScope
$policyResults = $policyRequests | Receive-PolManRequest

Write-Output "::endgroup::"

#* Initiatives
Write-Output "::group::Processing Initiative deployments"

$initiativeRequests = $initiativeFiles | Set-PolManInitiative -DefaultScope $defaultScope
$initiativeResults = $initiativeRequests | Receive-PolManRequest

Write-Output "::endgroup::"

#* Policy Assignments
Write-Output "::group::Processing Policy Assignments"

$policyAssignmentRequests = $policyAssignmentFiles | Set-PolManAssignment -AssignmentType "Policy" -DefaultScope $defaultScope -DefaultLocation $defaultLocation
$policyAssignmentResults = $policyAssignmentRequests | Receive-PolManRequest

#* Process role assignments
$policyAssignmentResults | Where-Object { $_.ResultState -eq "Completed" } | Set-PolManAssignmentRoleAssignment -DefaultScope $defaultScope

Write-Output "::endgroup::"

#* Initiative Assignments
Write-Output "::group::Processing Initiative Assignments"

$initiativeAssignmentRequests = $initiativeAssignmentFiles | Set-PolManAssignment -AssignmentType "Initiative" -DefaultScope $defaultScope -DefaultLocation $defaultLocation
$initiativeAssignmentResults = $initiativeAssignmentRequests | Receive-PolManRequest

#* Process role assignments
$initiativeAssignmentResults | Where-Object { $_.ResultState -eq "Completed" } | Set-PolManAssignmentRoleAssignment -DefaultScope $defaultScope

Write-Output "::endgroup::"

#* Exemptions
Write-Output "::group::Processing Exemptions"

$exemptionRequests = $exemptionFiles | Set-PolManExemption -MaxExpirationDateInDays $maxExemptionExpirationDateInDays -DefaultScope $defaultScope
$exemptionResults = $exemptionRequests | Receive-PolManRequest

Write-Output "::endgroup::"

#########################
###    IAC Cleanup    ###
#########################

# #* Only run loop if the trigger is timed
if ($Cleanup) {

    Write-Host "= ========================================"
    Write-Host "Starting IAC Cleanup."

    Write-Output "::group::Executing Policy Assignment Cleanup."
    #* Get policy assignments to remove
    $param = @{
        Path                             = $Path
        RootManagementGroupId            = $rootManagementGroupId 
        IgnoredPolicyCreatorPrincipalIds = $ignoredPolicyCreatorIdentities.principalId
    }
    $assignmentsToRemove = Get-PolicyAssignmentsToRemove @param

    Write-Host "Assignments to remove: $($assignmentsToRemove.Count)"
    $assignmentCleanupRequests = $assignmentsToRemove | Remove-PolManAssignment
    $assignmentCleanupResults = $assignmentCleanupRequests | Receive-PolManRequest

    Write-Output "::endgroup::"
    
    Write-Output "::group::Executing Exemption Cleanup."
    #* Get exemptions to remove
    $param = @{
        Path                  = $Path
        RootManagementGroupId = $rootManagementGroupId 
    }
    $exemptionsToRemove = Get-PolicyExemptionsToRemove @param

    Write-Host "Exemptions to remove: $($exemptionsToRemove.Count)"
    $exemptionCleanupRequests = $exemptionsToRemove | Remove-PolManExemption
    $exemptionCleanupResults = $exemptionCleanupRequests | Receive-PolManRequest
    
    Write-Output "::endgroup::"
}

Write-Output "::endgroup::"

#########################
###     Reporting     ###
#########################

$completedPolicies = ($policyResults + $initiativeResults) | Where-Object { $_.ResultState -in @("Completed") }
$failedPolicies = ($policyResults + $initiativeResults) | Where-Object { $_.ResultState -in @("Failed", "Stopped") }

$completedAssignments = ($policyAssignmentResults + $initiativeAssignmentResults) | Where-Object { $_.ResultState -in @("Completed") }
$failedAssignments = ($policyAssignmentResults + $initiativeAssignmentResults) | Where-Object { $_.ResultState -in @("Failed", "Stopped") }

$completedExemptions = $exemptionResults | Where-Object { $_.ResultState -in @("Completed") }
$failedExemptions = $exemptionResults | Where-Object { $_.ResultState -in @("Failed", "Stopped") }
$expiredExemptions = $exemptionResults | Where-Object { $_.ResultState -in @("Expired") }
$invalidExemptions = $exemptionResults | Where-Object { $_.ResultState -in @("Invalid") }

$completedAssignmentsCleanup = $assignmentCleanupResults | Where-Object { $_.ResultState -in @("Completed") }
$failedAssignmentsCleanup = $assignmentCleanupResults | Where-Object { $_.ResultState -in @("Failed", "Stopped") }

$completedExemptionsCleanup = $exemptionCleanupResults | Where-Object { $_.ResultState -in @("Completed") }
$failedExemptionsCleanup = $exemptionCleanupResults | Where-Object { $_.ResultState -in @("Failed", "Stopped") }

Write-Host "=====================================================CREATIONS/UPDATES======================================================"
Write-Host "Completed policies:`n" $($completedPolicies ? ($completedPolicies.Path | ForEach-Object { " - $_`n" }) : 'none')
Write-Host "Failed policies:   `n" $($failedPolicies ? ($failedPolicies.Path | ForEach-Object { " - $_`n" }) : 'none')
Write-Host ""
Write-Host "Completed assignments:`n" $($completedAssignments ? ($completedAssignments.Path | ForEach-Object { " - $_`n" }) : 'none')
Write-Host "Failed assignments:   `n" $($failedExemptions ? ($failedExemptions.Path | ForEach-Object { " - $_`n" }) : 'none')
Write-Host ""
Write-Host "Completed exemptions:`n" $($completedExemptions ? ($completedExemptions.Path | ForEach-Object { " - $_`n" }) : 'none')
Write-Host "Failed exemptions:   `n" $($failedExemptions ? ($failedExemptions.Path | ForEach-Object { " - $_`n" }) : 'none')
Write-Host "Invalid exemptions:  `n" $($expiredExemptions ? ($expiredExemptions.Path | ForEach-Object { " - $_`n" }) : 'none')
Write-Host "Expired exemptions:  `n" $($invalidExemptions ? ($invalidExemptions.Path | ForEach-Object { " - $_`n" }) : 'none')
Write-Host "==========================================================CLEAN-UP=========================================================="
Write-Host "Completed assignment cleanup:`n" $($completedAssignmentsCleanup ? ($completedAssignmentsCleanup.PolicyObject.Id | ForEach-Object { " - $_`n" }) : 'none')
Write-Host "Failed assignment cleanup:   `n" $($failedAssignmentsCleanup ? ($failedAssignmentsCleanup.PolicyObject.Id | ForEach-Object { " - $_`n" }) : 'none')
Write-Host ""
Write-Host "Completed exemption cleanup:`n" $($completedExemptionsCleanup ? ($completedExemptionsCleanup.PolicyObject.Id | ForEach-Object { " - $_`n" }) : 'none')
Write-Host "Failed exemption cleanup:   `n" $($failedExemptionsCleanup ? ($failedExemptionsCleanup.PolicyObject.Id | ForEach-Object { " - $_`n" }) : 'none')

#* Cleanup jobs
$resultCollections = @(
    $policyResults
    $initiativeResults
    $policyAssignmentResults
    $initiativeAssignmentResults
    $assignmentCleanupResults
    $exemptionCleanupResults
)
foreach ($resultCollection in $resultCollections) {
    $resultCollection.Job | Where-Object { $_ } | Remove-Job
}

exit ($failedPolicies).Count `
    + ($failedAssignments).Count `
    + ($failedExemptions).Count `
    + ($failedAssignmentsCleanup).Count `
    + ($failedExemptionsCleanup).Count

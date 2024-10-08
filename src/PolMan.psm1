$script:index_policyDefinitions_byScope = @{}
$script:index_initiativeDefinitions_byScope = @{}
$script:index_assignments_byScope = @{}
$script:index_exemptions_byScope = @{}

class PolManObject {
    [string]$Path
    [psobject]$FileObject
    [psobject]$PolicyObject
    [string]$ResultState
    [psobject]$Result
    [System.Management.Automation.Job]$Job
}

function Get-PolManPolicyFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateScript({ $_ | Test-Path -PathType Container })]
        [string]
        $Path,

        [Parameter(Mandatory)]
        [ValidateSet("Policy", "Initiative", "PolicyAssignment", "InitiativeAssignment", "Exemption")]
        [string]
        $Type,
    
        [Parameter(Mandatory = $false)]
        [string[]]
        $FilesToInclude,

        [Parameter(Mandatory = $false)]
        [string]
        $Pattern
    )

    $typePathPattern = @{
        Policy               = "\/policies\/[^\/]+?\/definitions\/[^\/]+?\.json$"
        Initiative           = "\/initiatives\/[^\/]+?\/definitions\/[^\/]+?\.json$"
        PolicyAssignment     = "\/policies\/[^\/]+?\/assignments\/[^\/]+?\.json$"
        InitiativeAssignment = "\/initiatives\/[^\/]+?\/assignments\/[^\/]+?\.json$"
        Exemption            = "\/(policies|initiatives)\/[^\/]+?\/exemptions\/[^\/]+?\.json$"
    }

    $directoryExclusionPattern = "\/([\w-]*?\.)?example[s]?\/"
    $fileExclusionPattern = "\/([\w-]*?\.)?example[s]?\.json$"

    #* Resolve full paths of FilesToInclude
    $filesToIncludeFullPaths = @()
    foreach ($includePath in $FilesToInclude) {
        if (Test-Path -Path $includePath) {
            $filesToIncludeFullPaths += (Resolve-Path -Path $includePath).Path
        }
    }

    #* Get files to process
    $files = Get-ChildItem -Path $Path -Recurse -Filter "*.json" | `
        Where-Object { $_.FullName -match $typePathPattern[$Type] }
    
    $result = @()
    foreach ($file in $files) {
        #* Get relative path
        $relativePath = Resolve-Path -Relative -Path $file.FullName

        #* Filter based on exclusions
        if ($relativePath -match $directoryExclusionPattern) {
            Write-Debug "Skipping. File path matches default exclusion pattern. File path: '$relativePath'. Pattern: '$directoryExclusionPattern'."
            continue
        }
        if ($relativePath -match $fileExclusionPattern) {
            Write-Debug "Skipping. File path matches default exclusion pattern. File path: '$relativePath'. Pattern: '$fileExclusionPattern'."
            continue
        }

        #* Filter based on changed files
        if ($PSBoundParameters.ContainsKey("FilesToInclude") -and $null -ne $FilesToInclude) {
            $include = $false
            foreach ($includePath in $filesToIncludeFullPaths) {
                if ($includePath -eq $file.FullName) {
                    $include = $true
                    break
                }
            }
            if (!$include) {
                Write-Debug "Skipping. FilesToInclude set and file path not present in FilesToInclude. File path: '$relativePath'."
                continue
            }
        }
    
        #* Filter based on pattern
        if ($Pattern -and $relativePath -notmatch $Pattern) {
            Write-Debug "Skipping. File path not matching pattern. File path: '$relativePath'. Pattern: '$Pattern'."
            continue
        }

        #* No filter met, adding
        Write-Debug "Adding. No filter met, adding file to result. File path: '$relativePath'."
        $result += $relativePath
    }

    $result | Write-Output
}

function Get-PolManPolicyObject {
    [CmdletBinding(DefaultParameterSetName = 'Id')]
    param (
        [Parameter(Mandatory,
            ParameterSetName = "Id",
            Position = 0)]
        [string]
        $Id,

        [Parameter(Mandatory,
            ParameterSetName = "Path")]
        [ValidateScript({ $_ | Test-Path -PathType Leaf })]
        [string]
        $Path,

        [Parameter(Mandatory,
            ParameterSetName = "Path")]
        [Parameter(Mandatory,
            ParameterSetName = "Scope")]
        [ValidateSet("Policy", "Initiative", "Assignment", "Exemption")]
        [string]
        $Type,

        [Parameter(Mandatory = $false,
            ParameterSetName = "Path")]
        [string]
        $DefaultScope,

        [Parameter(Mandatory = $false)]
        [switch]
        $Refresh,

        [Parameter(Mandatory = $false)]
        [int]
        $Depth = 30
    )

    switch ($PSCmdlet.ParameterSetName) {
        "Path" {
            $content = Get-Content -Path $Path | ConvertFrom-Json -Depth $Depth -AsHashtable
            $name = $content.name
            $scope = Resolve-Scope -Scope $content.scope -DefaultScope $DefaultScope
        }
        "Id" {
            $scope = $Id.Split("/providers/Microsoft.Authorization/")[0]
            $name = $Id.Split("/")[-1]
            $objectType = $Id.Split("/providers/Microsoft.Authorization/")[1].Split("/")[0]
            $Type = switch ($objectType) {
                "policyDefinitions" {
                    "Policy"
                }
                "policySetDefinitions" {
                    "Initiative"
                }
                "policyAssignments" {
                    "Assignment"
                }
                "policyExemptions" {
                    "Exemption"
                }
            }
        }
    }

    switch ($Type) {
        "Policy" {
            $index = $script:index_policyDefinitions_byScope
            $uri = "https://management.azure.com$($scope)/providers/Microsoft.Authorization/policyDefinitions?api-version=2023-04-01"
        }
        "Initiative" {
            $index = $script:index_initiativeDefinitions_byScope
            $uri = "https://management.azure.com$($scope)/providers/Microsoft.Authorization/policySetDefinitions?api-version=2023-04-01"
        }
        "Assignment" {
            $index = $script:index_assignments_byScope
            $uri = "https://management.azure.com$($scope)/providers/Microsoft.Authorization/policyAssignments?`$filter=atExactScope()&api-version=2023-04-01"
        }
        "Exemption" {
            $uri = "https://management.azure.com$($scope)/providers/Microsoft.Authorization/policyExemptions?`$filter=atExactScope()&api-version=2022-07-01-preview"
            $index = $script:index_exemptions_byScope
        }
    }
    
    #* Check if exists
    $indexScope = $scope -eq "" ? "/" : $scope
    $exists = $index.ContainsKey($indexScope) -and $index[$indexScope].ContainsKey($name)

    if (!$exists -or $Refresh) {
        $objects = [System.Collections.Generic.List[psobject]]::new()
        $nextLink = $uri
        do {
            $response = Invoke-AzRestMethod -Method "GET" -Uri $nextLink
            $content = $response.Content | ConvertFrom-Json -Depth $Depth -NoEnumerate
            foreach ($item in $content.value) {
                $objects.Add($item)
            }
            $nextLink = $content.nextLink
        }
        until (!$nextLink)
    
        if ($objects.Count -ge 1) {
            $index[$indexScope] = @{}
            foreach ($object in $objects) {
                $index[$indexScope].Add($object.Name, $object)
            }
        }
    }

    $index[$indexScope][$name]
}

function Set-PolManPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline = $true)]
        [ValidateScript({ $_ | Test-Path -PathType Leaf })]
        [string]
        $Path,

        [Parameter(Mandatory = $false)]
        [string]
        $DefaultScope,

        [Parameter(Mandatory = $false)]
        [int]
        $Depth = 30
    )

    process {
        Write-Host "Started [$Path]"

        $content = Get-Content -Path $Path | ConvertFrom-Json -Depth $Depth -AsHashtable
        $name = $content.name
        $scope = Resolve-Scope -Scope $content.scope -DefaultScope $DefaultScope

        $payload = @{
            properties = @{
                description = $content.properties.description
                displayName = $content.properties.displayName
                metadata    = $content.properties.metadata
                mode        = $content.properties.mode
                parameters  = $content.properties.parameters
                policyRule  = $content.properties.policyRule
                policyType  = $content.properties.policyType
            }
        }

        $param = @{
            Method  = "PUT"
            Uri     = "https://management.azure.com$($scope)/providers/Microsoft.Authorization/policyDefinitions/$($name)?api-version=2023-04-01"
            Payload = $payload | ConvertTo-Json -Depth $Depth
        }

        [PolManObject]@{
            Path         = $Path
            FileObject   = $content
            PolicyObject = $null
            ResultState  = $null
            Result       = $null
            Job          = Invoke-AzRestMethod @param -AsJob
        }
    }
}

function Set-PolManInitiative {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline = $true)]
        [ValidateScript({ $_ | Test-Path -PathType Leaf })]
        [string]
        $Path,

        [Parameter(Mandatory = $false)]
        [string]
        $DefaultScope,

        [Parameter(Mandatory = $false)]
        [int]
        $Depth = 30
    )

    process {
        Write-Host "Started [$Path]"
        $content = Get-Content -Path $Path | ConvertFrom-Json -Depth $Depth -AsHashtable
        $name = $content.name
        $scope = Resolve-Scope -Scope $content.scope -DefaultScope $DefaultScope

        $payload = @{
            properties = @{
                policyDefinitions      = $content.properties.policyDefinitions
                description            = $content.properties.description
                displayName            = $content.properties.displayName
                metadata               = $content.properties.metadata
                parameters             = $content.properties.parameters
                policyDefinitionGroups = $content.properties.policyDefinitionGroups
                policyType             = $content.properties.policyType
            }
        }

        $param = @{
            Method  = "PUT"
            Uri     = "https://management.azure.com$($scope)/providers/Microsoft.Authorization/policySetDefinitions/$($name)?api-version=2023-04-01"
            Payload = $payload | ConvertTo-Json -Depth $Depth
        }

        [PolManObject]@{
            Path         = $Path
            FileObject   = $content
            PolicyObject = $null
            ResultState  = $null
            Result       = $null
            Job          = Invoke-AzRestMethod @param -AsJob
        }
    }
}

function Set-PolManAssignment {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline = $true)]
        [ValidateScript({ $_ | Test-Path -PathType Leaf })]
        [string]
        $Path,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Policy", "Initiative")]
        [string]
        $AssignmentType,

        [Parameter(Mandatory = $false)]
        [string]
        $DefaultScope,

        [Parameter(Mandatory = $false)]
        [string]
        $DefaultLocation,

        [Parameter(Mandatory = $false)]
        [int]
        $Depth = 30
    )

    process {
        Write-Host "Processing [$Path]"
        $content = Get-Content -Path $Path | ConvertFrom-Json -Depth $Depth -AsHashtable
        $name = $content.name
        $scope = Resolve-Scope -Scope $content.scope -DefaultScope $DefaultScope

        $policyDefinitionId = $content.properties.policyDefinitionId
        if ($policyDefinitionId -notmatch "^\/") {
            $policyDefinitionId = switch ($AssignmentType) {
                "Policy" {
                    "$DefaultScope/providers/Microsoft.Authorization/policyDefinitions/$($content.properties.policyDefinitionId)"
                }
                "Initiative" {
                    "$DefaultScope/providers/Microsoft.Authorization/policySetDefinitions/$($content.properties.policyDefinitionId)"
                }
                default {
                    throw "When processing an assignment without a fully qualified scope property, the AssignmentType parameter must be specified."
                }
            }
        }

        $payload = @{
            properties = @{
                description           = $content.properties.description
                displayName           = $content.properties.displayName
                enforcementMode       = $content.properties.enforcementMode
                metadata              = $content.properties.metadata
                nonComplianceMessages = $content.properties.nonComplianceMessages
                notScopes             = $content.properties.notScopes
                overrides             = $content.properties.overrides
                parameters            = $content.properties.parameters
                policyDefinitionId    = $policyDefinitionId
                resourceSelectors     = $content.properties.resourceSelectors
            }
        }
        if ($content.identity) {
            $payload.Add("identity", $content.identity)
            $payload.Add("location", $content.location ?? $DefaultLocation)
        }

        $param = @{
            Method  = "PUT"
            Uri     = "https://management.azure.com$($scope)/providers/Microsoft.Authorization/policyAssignments/$($name)?api-version=2023-04-01"
            Payload = $payload | ConvertTo-Json -Depth $Depth
        }

        [PolManObject]@{
            Path         = $Path
            FileObject   = $content
            PolicyObject = $null
            ResultState  = $null
            Result       = $null
            Job          = Invoke-AzRestMethod @param -AsJob
        }
    }
}

function Set-PolManExemption {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline = $true)]
        [ValidateScript({ $_ | Test-Path -PathType Leaf })]
        [string]
        $Path,

        [Parameter(Mandatory = $false)]
        [int]
        $MaxExpirationDateInDays,

        [Parameter(Mandatory = $false)]
        [string]
        $DefaultScope,

        [Parameter(Mandatory = $false)]
        [int]
        $Depth = 30
    )

    process {
        Write-Host "Processing [$Path]"
        $content = Get-Content -Path $Path | ConvertFrom-Json -Depth $Depth -AsHashtable

        $polManObject = [PolManObject]@{
            Path         = $Path
            FileObject   = $content
            PolicyObject = $null
            Job          = $null
            ResultState  = $null
            Result       = $null
        }

        $sendRequest = $true
        
        #* Expiration date logic
        if ($content.properties.expiresOn -and $content.properties.expiresOn -ne "Never") {
            $daysUntilExpiration = ($content.properties.expiresOn - [datetime]::Now).TotalDays

            if ($daysUntilExpiration -lt 0) {
                #* Is expired
                $polManObject.ResultState = "Expired"
                $polManObject.Result = "The requested exemption is expired. Skipping."
                $sendRequest = $false
            }
            elseif ($daysUntilExpiration -gt $MaxExpirationDateInDays) {
                #* Exceeds allowed maximum number of days until expiration
                $polManObject.ResultState = "Invalid"
                $polManObject.Result = "The requested exemption 'expiresOn' property exceeds the configured 'MaxExemptionExpirationDateInDays'[$MaxExpirationDateInDays]"
                $sendRequest = $false
            }
        }

        if ($sendRequest) {
            $name = $content.name
            $scope = Resolve-Scope -Scope $content.scope -DefaultScope $DefaultScope
            
            $payload = @{
                properties = @{
                    exemptionCategory            = $content.properties.exemptionCategory
                    policyAssignmentId           = $content.properties.policyAssignmentId.startsWith("/") ? $content.properties.policyAssignmentId : "$DefaultScope/providers/Microsoft.Authorization/policyAssignments/$($content.properties.policyAssignmentId)"
                    assignmentScopeValidation    = $content.properties.assignmentScopeValidation
                    description                  = $content.properties.description
                    displayName                  = $content.properties.displayName
                    expiresOn                    = $content.properties.expiresOn
                    metadata                     = $content.properties.metadata
                    policyDefinitionReferenceIds = $content.properties.policyDefinitionReferenceIds
                    resourceSelectors            = $content.properties.resourceSelectors
                }
            }
    
            $param = @{
                Method  = "PUT"
                Uri     = "https://management.azure.com$($scope)/providers/Microsoft.Authorization/policyExemptions/$($name)?api-version=2022-07-01-preview"
                Payload = $payload | ConvertTo-Json -Depth $Depth
            }
    
            $polManObject.Job = Invoke-AzRestMethod @param -AsJob
        }
        else {
            $polManObject
        }
    }
}

function Set-PolManAssignmentRoleAssignment {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline)]
        [PolManObject]
        $PolManObject,

        [Parameter(Mandatory = $false)]
        [string]
        $DefaultScope,

        [Parameter(Mandatory = $false)]
        [int]
        $Depth = 30
    )

    process {
        Write-Host "Processing [$($PolManObject.Path)]"
        $content = $PolManObject.FileObject
        $assignmentObject = $PolManObject.PolicyObject

        #* Find all child policies
        $definitionObject = Get-PolManPolicyObject -Id $assignmentObject.properties.policyDefinitionId
        $childPolicyDefinitions = @()
        switch ($definitionObject.type) {
            "Microsoft.Authorization/policyDefinitions" {
                $childPolicyDefinitions += $definitionObject
            }
            "Microsoft.Authorization/policySetDefinitions" {
                foreach ($childPolicyDefinition in $definitionObject.properties.policyDefinitions) {
                    $childPolicyDefinitions += Get-PolManPolicyObject -Id $childPolicyDefinition.policyDefinitionId
                }
            }
        }

        #* Find all child policy roleDefinitionIds
        $roleDefinitionIds = foreach ($childPolicyDefinition in $childPolicyDefinitions) {
            foreach ($roleDefinitionId in $childPolicyDefinition.properties.policyRule.then.details.roleDefinitionIds) {
                $roleDefinitionId
            }
        }
        $roleDefinitionIds = $roleDefinitionIds | Sort-Object -Unique | ForEach-Object { $_.Split('/')[-1] }

        #* Create list of assignments
        $rolesToAdd = $content.roleAssignments ?? @()
        foreach ($roleDefinitionId in $roleDefinitionIds) {
            if ($rolesToAdd | Where-Object { $_.scope -eq $assignmentObject.properties.scope -and $_.roleDefinitionId -eq $roleDefinitionId }) {
                Write-Debug "Role assignment already specified in assignment file. Scope: $($assignmentObject.properties.scope). RoleDefinitionId: $roleDefinitionId"
            }
            else {
                $rolesToAdd += @{
                    scope            = $assignmentObject.properties.scope
                    roleDefinitionId = $roleDefinitionId
                }
            }
        }

        #* Create assignments
        if ($assignmentObject.identity -and $rolesToAdd.Count -gt 0) {
            foreach ($role in $rolesToAdd) {
                #* Check for existing role assignment
                $param = @{
                    Scope            = $role.scope
                    ObjectId         = $assignmentObject.identity.principalId
                    RoleDefinitionId = $role.roleDefinitionId.Split("/")[-1]
                    ErrorAction      = 'Stop'
                }
                $roleAssignment = Get-AzRoleAssignment @param
                
                #* Create role assignment
                if ($roleAssignment) {
                    Write-Host "Role [$($roleAssignment.RoleDefinitionName)] already granted over [$($role.scope)] to managed identity [$($assignmentObject.identity.principalId)]"
                }
                else {
                    $param.Add("Description", $role.description ?? $assignmentObject.DisplayName ?? $assignmentObject.Name)
                    $param.Add("PrincipalType", "ServicePrincipal")
                    $roleAssignment = New-AzRoleAssignment @param
                    Write-Host "Granted role [$($roleAssignment.RoleDefinitionName)] over [$($role.scope)] to managed identity [$($assignmentObject.identity.principalId)]"
                }
            }
        }
    }
}

function Receive-PolManRequest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline)]
        [PolManObject]
        $PolManObject,

        [Parameter(Mandatory = $false)]
        [int]
        $Timeout,

        [Parameter(Mandatory = $false)]
        [int]
        $Depth = 30
    )

    begin {
        $list = [System.Collections.Generic.List[object]]::new()

        $finishedStates = @(
            "Completed"
            "Failed"
            "Stopped"
        )
    
        $start = Get-Date
    }
    process {
        $list.Add($PolManObject)
    }
    end {
        $Timeout = $Timeout -gt 0 ? $Timeout : ([Math]::Min([Math]::Max($list.Count * 3, 30), 300))
        do {
            $allFinished = $true
            foreach ($polManObject_i in ($list | Where-Object { !$_.ResultState })) {
                $job = $polManObject_i.Job
                if ($job.State -in $finishedStates) {
                    $polManObject_i.Result = $job | Receive-Job
                    $polManObject_i.ResultState = $job.State
                    if ($job.State -eq "Completed") {
                        $resultContent = $polManObject_i.Result.Content | ConvertFrom-Json -Depth $Depth -NoEnumerate
                        if ($polManObject_i.Result.StatusCode -in 200..299) {
                            $polManObject_i.PolicyObject = $resultContent
                        }
                        else {
                            $polManObject_i.ResultState = "Failed"
                            Write-Error -Exception $resultContent.error.code -Message $resultContent.error.message
                        }
                    }
                }
                else {
                    $allFinished = $false
                }
            }
            $timeoutReached = ([datetime]::Now - $start).TotalSeconds -gt $Timeout

            if ($timeoutReached) {
                throw "Not all jobs finished within specified timeout ($Timeout seconds). Aborting."
            }
            if (!$allFinished) {
                Start-Sleep -Seconds 1
            }
        }
        until ($allFinished)

        #* Return
        $list
    }
}

function Resolve-Scope {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]
        $Scope,

        [Parameter(Mandatory = $false)]
        [string]
        $DefaultScope
    )

    if ($content.scope) {
        $content.scope
    }
    elseif ($DefaultScope) {
        $DefaultScope
    }
    else {
        throw "Scope property not set in policy file and DefaultScope parameter not specified."
    }
}

function Get-PolicyScopes {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ParameterSetName = "Name")]
        [string]
        $ManagementGroupName,

        [Parameter(Mandatory,
            DontShow,
            ParameterSetName = "Object")]
        [Microsoft.Azure.Commands.Resources.Models.ManagementGroups.PSManagementGroupChildInfo]
        $ChildObject,

        [Parameter(Mandatory = $false)]
        [switch]
        $Recurse
    )

    #* Get Management Group object
    if ($ChildObject) {
        $enumerableObject = $ChildObject
    }
    else {
        $enumerableObject = Get-AzManagementGroup -GroupName $ManagementGroupName -Expand -Recurse
    }

    #* Recurse
    if ($Recurse) {
        foreach ($child in $enumerableObject.Children) {
            Get-PolicyScopes -ChildObject $child -Recurse
        }
    }
        
    #* Return
    $enumerableObject.Id
}

function Get-PolicyExemptions {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $ManagementGroupName
    )

    $kqlQuery = "PolicyResources | where type == 'microsoft.authorization/policyexemptions'"
    $batchSize = 100

    $objects = [System.Collections.Generic.List[psobject]]::new()
    $skipToken = $null
    do {
        $response = Search-AzGraph -Query $kqlQuery -ManagementGroup $ManagementGroupName -First $batchSize -SkipToken $skipToken
        foreach ($item in $response.Data) {
            $objects.Add($item)
        }
        $skipToken = $response.SkipToken
    }
    until (!$skipToken)

    $objects
}

function Get-PolicyAssignments {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $ManagementGroupName
    )

    $kqlQuery = "PolicyResources | where type == 'microsoft.authorization/policyassignments'"
    $batchSize = 100

    $objects = [System.Collections.Generic.List[psobject]]::new()
    $skipToken = $null
    do {
        $response = Search-AzGraph -Query $kqlQuery -ManagementGroup $ManagementGroupName -First $batchSize -SkipToken $skipToken
        foreach ($item in $response.Data) {
            $objects.Add($item)
        }
        $skipToken = $response.SkipToken
    }
    until (!$skipToken)

    $objects
}

function Get-PolicyAssignmentsToRemove {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateScript({ $_ | Test-Path -PathType Container })]
        [string]
        $Path,

        [Parameter(Mandatory)]
        [string]
        $RootManagementGroupId,

        [Parameter(Mandatory = $false)]
        [string[]]
        $IgnoredPolicyCreatorPrincipalIds = @()
    )
    
    $currentAssignments = Get-PolicyAssignments -ManagementGroupName $RootManagementGroupId

    $allPolicyAssignmentFiles = Get-PolManPolicyFile -Path $Path -Type "PolicyAssignment" -Pattern ".*"
    $allInitiativeAssignmentFiles = Get-PolManPolicyFile -Path $Path -Type "InitiativeAssignment" -Pattern ".*"

    $allAssignments = @()
    foreach ($assignmentFile in $allPolicyAssignmentFiles + $allInitiativeAssignmentFiles) {
        $allAssignments += Get-PolManPolicyObject -Path $assignmentFile -Type "Assignment"
    }

    $assignmentsToRemove = @()
    foreach ($assignment in $currentAssignments) {
        $assignmentObject = Get-PolManPolicyObject -Id $assignment.id

        if ($assignmentObject.id -notin $allAssignments.id) {
            if ($assignmentObject.properties.metadata.updatedBy -in $ignoredPolicyCreatorIdentities.principalId) {
                continue
            }
            if ($assignmentObject.properties.metadata.createdBy -in $ignoredPolicyCreatorIdentities.principalId) {
                continue
            }

            $assignmentsToRemove += $assignmentObject
        }
    }

    $assignmentsToRemove
}

function Get-PolicyExemptionsToRemove {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateScript({ $_ | Test-Path -PathType Container })]
        [string]
        $Path,

        [Parameter(Mandatory)]
        [string]
        $RootManagementGroupId
    )
    
    $currentExemptions = Get-PolicyExemptions -ManagementGroupName $RootManagementGroupId

    $allExemptionFiles = Get-PolManPolicyFile -Path $Path -Type "Exemption" -Pattern ".*"

    $allExemptions = @()
    foreach ($exemptionFile in $allExemptionFiles) {
        $allExemptions += Get-PolManPolicyObject -Path $exemptionFile -Type "Exemption"
    }

    $exemptionsToRemove = @()
    foreach ($exemption in $currentExemptions) {
        $exemptionObject = Get-PolManPolicyObject -Id $exemption.id

        if ($exemptionObject.id -notin $allExemptions.id) {
            $exemptionsToRemove += $exemptionObject
        }
    }

    $exemptionsToRemove
}

function Remove-PolManAssignment {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline = $true)]
        [psobject]
        $PolicyObject,

        [Parameter(Mandatory = $false)]
        [int]
        $Depth
    )

    process {
        Write-Host "Started [$($PolicyObject.id)]"
        $param = @{
            Method = "GET"
            Uri    = "https://management.azure.com$($PolicyObject.id)?api-version=2023-04-01"
        }

        [PolManObject]@{
            Path         = $null
            FileObject   = $null
            PolicyObject = $PolicyObject
            ResultState  = $null
            Result       = $null
            Job          = Invoke-AzRestMethod @param -AsJob
        }
    }
}

function Remove-PolManExemption {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline = $true)]
        [psobject]
        $PolicyObject,

        [Parameter(Mandatory = $false)]
        [int]
        $Depth
    )

    process {
        Write-Host "Started [$($PolicyObject.id)]"
        $param = @{
            Method = "GET"
            Uri    = "https://management.azure.com$($PolicyObject.id)?api-version=2022-07-01-preview"
        }

        [PolManObject]@{
            Path         = $null
            FileObject   = $null
            PolicyObject = $PolicyObject
            ResultState  = $null
            Result       = $null
            Job          = Invoke-AzRestMethod @param -AsJob
        }
    }
}
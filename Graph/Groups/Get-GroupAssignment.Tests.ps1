# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/zenpachi-alt/endpoint-engineering

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

<#
.SYNOPSIS
    Pester tests for Get-GroupAssignment.ps1: how it finds the group and its
    parents, how it reads each kind of assignment, and above all that nothing
    it could not read passes for an assignment that is not there.

.DESCRIPTION
    The script's functions are loaded from its syntax tree, without running
    its main block, and Get-GraphCollection and Invoke-GraphRequestWithRetry
    are replaced by a stand-in tenant held in memory, keyed by URI. A URI the
    script should not be asking for fails here. Nothing reaches Graph and no
    module is needed.

    The script is also started as a file, in a child process, for its exit
    code and its message. That gets past the script's module check, so it is
    skipped where Microsoft.Graph.Authentication is not installed.

    Identifier-shaped values are built at run time, so this file passes
    Tools/Test-SensitiveContent.ps1 like any other.

.EXAMPLE
    Invoke-Pester -Path .\Graph\Groups\Get-GroupAssignment.Tests.ps1 -Output Detailed

.NOTES
    PowerShell    : 5.1 or 7.
    Graph scopes  : None. Nothing reaches a tenant.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : Pester 5.5.0 or later.
                    Microsoft.Graph.Authentication 2.0.0 or later, optional,
                    for the test of the script run as a file.
#>

BeforeDiscovery {
    # The script loads the module before anything else, so it gets as far as
    # its own checks only where the module is installed for the PowerShell
    # that runs the tests.
    $script:ModuleAvailable = [bool](Get-Module -ListAvailable -Name Microsoft.Graph.Authentication |
            Where-Object { $_.Version -ge [version]'2.0.0' })
}

BeforeAll {
    $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'Get-GroupAssignment.ps1'
    $script:ScriptPath = $scriptPath

    # Every top-level function of the script, without the main block.
    $parseErrors = $null
    $syntaxTree = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$parseErrors)
    if ($parseErrors) { throw "Get-GroupAssignment.ps1 does not parse: $($parseErrors[0].Message)" }
    foreach ($statement in $syntaxTree.EndBlock.Statements) {
        if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
            . ([scriptblock]::Create($statement.Extent.Text))
        }
    }
    $script:SyntaxTree = $syntaxTree

    $script:V1 = 'https://graph.microsoft.com/v1.0'
    $script:Beta = 'https://graph.microsoft.com/beta'
    $script:Reads = [System.Collections.Generic.List[string]]::new()
    $script:Attempts = [System.Collections.Generic.List[int]]::new()
    $script:Tenant = @{}

    # Defined after the script's functions, so they replace the helpers. They
    # take only the parameters the script passes, so a new one fails here. A
    # value in the tenant that is an exception is thrown, as the helper would.
    function Get-GraphCollection {
        param ([Parameter(Mandatory)][string]$Uri, [int]$MaximumAttempt)

        $script:Reads.Add($Uri)
        $script:Attempts.Add($MaximumAttempt)
        if (-not $script:Tenant.ContainsKey($Uri)) { throw "The stand-in tenant has no collection at $Uri" }
        if ($script:Tenant[$Uri] -is [System.Exception]) { throw $script:Tenant[$Uri] }

        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($item in @($script:Tenant[$Uri])) { $items.Add($item) }
        return , $items
    }

    function Invoke-GraphRequestWithRetry {
        param ([Parameter(Mandatory)][string]$Uri, [int]$MaximumAttempt)

        $script:Reads.Add($Uri)
        $script:Attempts.Add($MaximumAttempt)
        if (-not $script:Tenant.ContainsKey($Uri)) { throw "The stand-in tenant has nothing at $Uri" }
        if ($script:Tenant[$Uri] -is [System.Exception]) { throw $script:Tenant[$Uri] }
        return $script:Tenant[$Uri]
    }

    function Get-GraphFailure {
        # The exception the real helper throws: the status in Data.
        param ([int]$StatusCode, [string]$Message = 'Refused')

        $exception = [System.Exception]::new("HTTP $StatusCode from Graph after 1 attempt(s): $Message")
        $exception.Data['StatusCode'] = $StatusCode
        $exception
    }

    function Get-Target {
        # An assignment as Graph returns it.
        param (
            [string]$GroupId,
            [string]$Type = 'groupAssignmentTarget',
            [string]$IdProperty = 'groupId',
            [string]$FilterId,
            [string]$FilterMode,
            [string]$Intent,
            [string]$Source
        )

        $target = [ordered]@{ '@odata.type' = "#microsoft.graph.$Type" }
        if ($GroupId) { $target[$IdProperty] = $GroupId }
        if ($FilterId) { $target['deviceAndAppManagementAssignmentFilterId'] = $FilterId }
        if ($FilterMode) { $target['deviceAndAppManagementAssignmentFilterType'] = $FilterMode }

        $assignment = [ordered]@{ id = [guid]::NewGuid().ToString(); target = [pscustomobject]$target }
        if ($Intent) { $assignment['intent'] = $Intent }
        if ($Source) { $assignment['source'] = $Source }
        [pscustomobject]$assignment
    }

    function Add-StandInObject {
        # An object in a source's list, and its assignments.
        param (
            [string]$Path,
            [string]$Name,
            [object[]]$Assignment = @(),
            [string]$NameProperty = 'displayName',
            [string]$Id = [guid]::NewGuid().ToString()
        )

        $listUri = "$script:Beta/$Path"
        if (-not $script:Tenant.ContainsKey($listUri)) { $script:Tenant[$listUri] = @() }
        $script:Tenant[$listUri] = @($script:Tenant[$listUri]) + @([pscustomobject]@{ id = $Id; $NameProperty = $Name })
        $script:Tenant["$listUri/$Id/assignments"] = $Assignment
        $Id
    }

    function Get-Source {
        # The source with this path, as the script describes it.
        param ([string]$Path)

        $source = @(Get-AssignmentSource | Where-Object { $_.Path -eq $Path })
        if ($source.Count -ne 1) { throw "No single source has the path $Path." }
        $source[0]
    }

    function Find-One {
        # Searches a source for the group alone and returns the result.
        param ([string]$Path, [hashtable]$Target)

        Find-SourceAssignment -Source (Get-Source -Path $Path) -Target $Target -BaseUri $script:Beta
    }

    function Get-DirectTarget {
        param ([string]$GroupId, [string]$Name = 'Example group')

        @{ $GroupId = [pscustomobject]@{ Id = $GroupId; DisplayName = $Name; Relationship = 'Direct' } }
    }

    function Clear-StandInTenant {
        # An empty tenant and a new group for each test.
        $script:Reads.Clear()
        $script:Attempts.Clear()
        $script:Tenant = @{}
        $script:GroupId = [guid]::NewGuid().ToString()
    }
}

Describe 'Get-AssignmentSource' {

    It 'has a source for every category -Category offers, and no other' {
        $parameter = $script:SyntaxTree.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Category' }
        $validateSet = $parameter.Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateSet' }
        $offered = @($validateSet.PositionalArguments | ForEach-Object { $_.Value } | Sort-Object)

        @(Get-AssignmentSource | ForEach-Object { $_.Category } | Sort-Object -Unique) | Should -Be $offered
    }

    It 'searches every category by default' {
        $parameter = $script:SyntaxTree.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Category' }
        $defaults = @($parameter.DefaultValue.FindAll({ param ($node) $node -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true) |
                ForEach-Object { $_.Value } | Sort-Object)

        $defaults | Should -Be @(Get-AssignmentSource | ForEach-Object { $_.Category } | Sort-Object -Unique)
    }

    It 'lists each path once, and gives each source a label' {
        $sources = @(Get-AssignmentSource)

        @($sources | ForEach-Object { $_.Path } | Sort-Object -Unique).Count | Should -Be $sources.Count
        @($sources | Where-Object { -not $_.Label }).Count | Should -Be 0
    }

    It 'keeps labels short enough for the summary table' {
        @(Get-AssignmentSource | Where-Object { $_.Label.Length -gt 29 }).Count | Should -Be 0
    }

    It 'expands the macOS scripts, whose assignments path answers HTTP 400' {
        (Get-Source -Path 'deviceManagement/deviceShellScripts').Read | Should -Be 'Expand'
        (Get-Source -Path 'deviceManagement/deviceCustomAttributeShellScripts').Read | Should -Be 'Expand'
    }

    It 'reads apps object by object, since expanding the list is deprecated' {
        (Get-Source -Path 'deviceAppManagement/mobileApps').Read | Should -Be 'Assignments'
    }
}

Describe 'Get-RequiredScope' {

    It 'always asks for what the group and the filter names need' {
        $scopes = Get-RequiredScope -Category 'CompliancePolicies'

        @($scopes.Keys) | Should -Be @('DeviceManagementConfiguration.Read.All', 'GroupMember.Read.All')
    }

    It 'adds a scope for a category that needs its own' -ForEach @(
        @{ Category = 'Scripts'; Scope = 'DeviceManagementScripts.Read.All' }
        @{ Category = 'Apps'; Scope = 'DeviceManagementApps.Read.All' }
        @{ Category = 'Enrollment'; Scope = 'DeviceManagementServiceConfig.Read.All' }
        @{ Category = 'Roles'; Scope = 'DeviceManagementRBAC.Read.All' }
    ) {
        @((Get-RequiredScope -Category $Category).Keys) | Should -Contain $Scope
    }

    It 'asks for nothing a category left out would need' {
        @((Get-RequiredScope -Category 'Apps').Keys) | Should -Not -Contain 'DeviceManagementRBAC.Read.All'
    }

    It 'accepts the ReadWrite scope in place of each Read scope' {
        $scopes = Get-RequiredScope -Category 'Scripts', 'Apps', 'Enrollment', 'Roles'

        foreach ($name in $scopes.Keys) { @($scopes[$name]) | Should -Contain ($name -replace '\.Read\.All$', '.ReadWrite.All') }
    }

    It 'accepts a broader group scope already granted' {
        $alternatives = @((Get-RequiredScope -Category 'Apps')['GroupMember.Read.All'])

        $alternatives | Should -Contain 'Group.Read.All'
        $alternatives | Should -Contain 'Directory.Read.All'
    }
}

Describe 'Resolve-TargetGroup' {

    BeforeAll {
        function Get-NameUri {
            param ([string]$Name)

            $filter = [uri]::EscapeDataString("displayName eq '$Name'")
            "$script:V1/groups?`$filter=$filter&`$select=id,displayName,createdDateTime&`$top=999"
        }
    }

    BeforeEach {
        Clear-StandInTenant
    }

    Context 'by name' {

        It 'finds the one group with that name' {
            $script:Tenant[(Get-NameUri -Name 'Pilot')] = @([pscustomobject]@{ id = $script:GroupId; displayName = 'Pilot' })

            $group = Resolve-TargetGroup -GroupName 'Pilot' -BaseUri $script:V1

            $group.Id | Should -Be $script:GroupId
            $group.DisplayName | Should -Be 'Pilot'
            $group.Exists | Should -BeTrue
        }

        It 'trims the name' {
            $script:Tenant[(Get-NameUri -Name 'Pilot')] = @([pscustomobject]@{ id = $script:GroupId; displayName = 'Pilot' })

            (Resolve-TargetGroup -GroupName '  Pilot ' -BaseUri $script:V1).Id | Should -Be $script:GroupId
        }

        It 'doubles a quote in the name, so the filter stays valid' {
            $script:Tenant[(Get-NameUri -Name "Tom''s devices")] = @([pscustomobject]@{ id = $script:GroupId; displayName = "Tom's devices" })

            (Resolve-TargetGroup -GroupName "Tom's devices" -BaseUri $script:V1).Id | Should -Be $script:GroupId
        }

        It 'stops when no group has the name' {
            $script:Tenant[(Get-NameUri -Name 'Nobody')] = @()

            { Resolve-TargetGroup -GroupName 'Nobody' -BaseUri $script:V1 } | Should -Throw "*No group is named 'Nobody'*"
        }

        It 'chooses none of the groups that share a name, and lists them' {
            $second = [guid]::NewGuid().ToString()
            $script:Tenant[(Get-NameUri -Name 'Pilot')] = @(
                [pscustomobject]@{ id = $script:GroupId; displayName = 'Pilot'; createdDateTime = '2026-01-02T03:04:05Z' }
                [pscustomobject]@{ id = $second; displayName = 'Pilot'; createdDateTime = '2026-02-03T04:05:06Z' }
            )

            { Resolve-TargetGroup -GroupName 'Pilot' -BaseUri $script:V1 } |
                Should -Throw "*2 groups are named 'Pilot'*$($script:GroupId)*$second*"
        }
    }

    Context 'by object ID' {

        BeforeEach {
            $script:IdUri = "$script:V1/groups/$($script:GroupId)?`$select=id,displayName,createdDateTime"
        }

        It 'reads the group' {
            $script:Tenant[$script:IdUri] = [pscustomobject]@{ id = $script:GroupId; displayName = 'Pilot' }

            $group = Resolve-TargetGroup -GroupId $script:GroupId -BaseUri $script:V1

            $group.DisplayName | Should -Be 'Pilot'
            $group.Exists | Should -BeTrue
        }

        It 'goes on, with a warning, for a group that does not exist' {
            $script:Tenant[$script:IdUri] = Get-GraphFailure -StatusCode 404

            $group = Resolve-TargetGroup -GroupId $script:GroupId -BaseUri $script:V1 -WarningVariable warned -WarningAction SilentlyContinue

            $group.Exists | Should -BeFalse
            $group.Id | Should -Be $script:GroupId
            "$warned" | Should -BeLike '*can outlive its group*'
        }

        It 'does not take a refusal for a missing group' {
            $script:Tenant[$script:IdUri] = Get-GraphFailure -StatusCode 403

            { Resolve-TargetGroup -GroupId $script:GroupId -BaseUri $script:V1 } | Should -Throw '*HTTP 403*'
        }
    }
}

Describe 'Get-ParentGroup' {

    BeforeEach {
        Clear-StandInTenant
        $script:ParentUri ="$script:V1/groups/$($script:GroupId)/transitiveMemberOf?`$select=id,displayName"
    }

    It 'returns the groups the group is nested in' {
        $parent = [guid]::NewGuid().ToString()
        $script:Tenant[$script:ParentUri] = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.group'; id = $parent; displayName = 'Parent' })

        $found = @(Get-ParentGroup -GroupId $script:GroupId -BaseUri $script:V1)

        $found.Count | Should -Be 1
        $found[0].Id | Should -Be $parent
        $found[0].DisplayName | Should -Be 'Parent'
    }

    It 'drops directory roles and administrative units, which cannot be targets' {
        $script:Tenant[$script:ParentUri] = @(
            [pscustomobject]@{ '@odata.type' = '#microsoft.graph.directoryRole'; id = [guid]::NewGuid().ToString(); displayName = 'A role' }
            [pscustomobject]@{ '@odata.type' = '#microsoft.graph.administrativeUnit'; id = [guid]::NewGuid().ToString(); displayName = 'A unit' }
        )

        @(Get-ParentGroup -GroupId $script:GroupId -BaseUri $script:V1).Count | Should -Be 0
    }

    It 'keeps a row with no type, rather than risk hiding an assignment' {
        $script:Tenant[$script:ParentUri] = @([pscustomobject]@{ id = [guid]::NewGuid().ToString(); displayName = 'Unknown' })

        @(Get-ParentGroup -GroupId $script:GroupId -BaseUri $script:V1).Count | Should -Be 1
    }

    It 'lets a failed read reach the caller' {
        $script:Tenant[$script:ParentUri] = Get-GraphFailure -StatusCode 403

        { Get-ParentGroup -GroupId $script:GroupId -BaseUri $script:V1 } | Should -Throw '*HTTP 403*'
    }
}

Describe 'Get-ObjectDisplayName' {

    It 'reads displayName' {
        Get-ObjectDisplayName -InputObject ([pscustomobject]@{ displayName = 'Profile' }) | Should -Be 'Profile'
    }

    It 'reads name, as configurationPolicies have' {
        Get-ObjectDisplayName -InputObject ([pscustomobject]@{ name = 'Catalog policy' }) | Should -Be 'Catalog policy'
    }

    It 'says so when there is neither' {
        Get-ObjectDisplayName -InputObject ([pscustomobject]@{ id = 'x' }) | Should -Be '(no name)'
    }
}

Describe 'ConvertTo-AssignmentEntry' {

    BeforeEach {
        Clear-StandInTenant
    }

    It 'reads an included group' {
        $entry = ConvertTo-AssignmentEntry -Assignment (Get-Target -GroupId $script:GroupId)

        $entry.GroupId | Should -Be $script:GroupId
        $entry.Assignment | Should -Be 'Include'
    }

    It 'reads an excluded group' {
        $entry = ConvertTo-AssignmentEntry -Assignment (Get-Target -GroupId $script:GroupId -Type 'exclusionGroupAssignmentTarget')

        $entry.Assignment | Should -Be 'Exclude'
    }

    It 'reads a group held in entraObjectId, as a scope tag group target has it' {
        $assignment = Get-Target -GroupId $script:GroupId -Type 'scopeTagGroupAssignmentTarget' -IdProperty 'entraObjectId'

        (ConvertTo-AssignmentEntry -Assignment $assignment).GroupId | Should -Be $script:GroupId
    }

    It 'returns nothing for a target that names no group by design' -ForEach @(
        @{ Type = 'allDevicesAssignmentTarget' }
        @{ Type = 'allLicensedUsersAssignmentTarget' }
        @{ Type = 'configurationManagerCollectionAssignmentTarget' }
    ) {
        @(ConvertTo-AssignmentEntry -Assignment (Get-Target -Type $Type)).Count | Should -Be 0
    }

    It 'reads a type without its leading #, as the documentation shows it' {
        $assignment = [pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = 'microsoft.graph.allDevicesAssignmentTarget' } }

        @(ConvertTo-AssignmentEntry -Assignment $assignment).Count | Should -Be 0
    }

    It 'returns an entry with no group for a target it cannot read' {
        $entry = ConvertTo-AssignmentEntry -Assignment (Get-Target -Type 'someFutureAssignmentTarget')

        $entry.GroupId | Should -BeNullOrEmpty
    }

    It 'returns an entry with no group for an assignment with no target' {
        $entry = ConvertTo-AssignmentEntry -Assignment ([pscustomobject]@{ id = 'x' })

        $entry.GroupId | Should -BeNullOrEmpty
    }

    It 'keeps the intent and the source' {
        $entry = ConvertTo-AssignmentEntry -Assignment (Get-Target -GroupId $script:GroupId -Intent 'required' -Source 'policySets')

        $entry.Intent | Should -Be 'required'
        $entry.Source | Should -Be 'policySets'
    }

    It 'keeps a filter' {
        $filterId = [guid]::NewGuid().ToString()
        $entry = ConvertTo-AssignmentEntry -Assignment (Get-Target -GroupId $script:GroupId -FilterId $filterId -FilterMode 'exclude')

        $entry.FilterId | Should -Be $filterId
        $entry.FilterMode | Should -Be 'exclude'
    }

    It 'treats an empty filter ID as no filter' {
        $assignment = Get-Target -GroupId $script:GroupId -FilterId ([guid]::Empty.ToString()) -FilterMode 'none'
        $entry = ConvertTo-AssignmentEntry -Assignment $assignment

        $entry.FilterId | Should -BeNullOrEmpty
        $entry.FilterMode | Should -BeNullOrEmpty
    }
}

Describe 'Get-RoleAssignmentEntry' {

    BeforeEach {
        Clear-StandInTenant
    }

    It 'reads members and scope groups' {
        $scope = [guid]::NewGuid().ToString()
        $role = [pscustomobject]@{ members = @($script:GroupId); resourceScopes = @($scope) }

        $entries = @(Get-RoleAssignmentEntry -RoleAssignment $role)

        @($entries | Where-Object { $_.Assignment -eq 'RoleMember' }).GroupId | Should -Be $script:GroupId
        @($entries | Where-Object { $_.Assignment -eq 'RoleScope' }).GroupId | Should -Be $scope
    }

    It 'reads scope groups from either property, and reports one named by both once' {
        $both = [guid]::NewGuid().ToString()
        $other = [guid]::NewGuid().ToString()
        $role = [pscustomobject]@{ members = @(); resourceScopes = @($both); scopeMembers = @($both, $other) }

        $scopes = @(Get-RoleAssignmentEntry -RoleAssignment $role | ForEach-Object { $_.GroupId })

        $scopes.Count | Should -Be 2
        $scopes | Should -Contain $both
        $scopes | Should -Contain $other
    }

    It 'returns nothing for a role that names no group' {
        @(Get-RoleAssignmentEntry -RoleAssignment ([pscustomobject]@{ members = @(); resourceScopes = @() })).Count | Should -Be 0
    }

    It 'refuses a response with no members list, which would pass for none' {
        { Get-RoleAssignmentEntry -RoleAssignment ([pscustomobject]@{ id = 'x' }) } | Should -Throw "*no 'members' list*"
    }
}

Describe 'Find-SourceAssignment' {

    BeforeEach {
        Clear-StandInTenant
    }

    Context 'matching' {

        It 'records an assignment to the group' {
            $id = Add-StandInObject -Path 'deviceManagement/deviceConfigurations' -Name 'Wi-Fi' -Assignment @(Get-Target -GroupId $script:GroupId)

            $result = Find-One -Path 'deviceManagement/deviceConfigurations' -Target (Get-DirectTarget -GroupId $script:GroupId)

            $result.Records.Count | Should -Be 1
            $result.Records[0].ObjectName | Should -Be 'Wi-Fi'
            $result.Records[0].ObjectId | Should -Be $id
            $result.Records[0].ObjectType | Should -Be 'Device configuration profile'
            $result.Records[0].Category | Should -Be 'ConfigurationProfiles'
            $result.Records[0].Assignment | Should -Be 'Include'
            $result.Records[0].Relationship | Should -Be 'Direct'
            $result.Records[0].AssignedGroup | Should -Be 'Example group'
            $result.Records[0].AssignedGroupId | Should -Be $script:GroupId
        }

        It 'leaves out assignments to other groups' {
            $null = Add-StandInObject -Path 'deviceManagement/deviceConfigurations' -Name 'Other' -Assignment @(Get-Target -GroupId ([guid]::NewGuid().ToString()))

            $result = Find-One -Path 'deviceManagement/deviceConfigurations' -Target (Get-DirectTarget -GroupId $script:GroupId)

            $result.Records.Count | Should -Be 0
            $result.Coverage.Status | Should -Be 'Complete'
        }

        It 'compares group IDs without regard to case' {
            $null = Add-StandInObject -Path 'deviceManagement/deviceConfigurations' -Name 'Wi-Fi' -Assignment @(Get-Target -GroupId $script:GroupId.ToUpperInvariant())

            $result = Find-One -Path 'deviceManagement/deviceConfigurations' -Target (Get-DirectTarget -GroupId $script:GroupId)

            $result.Records.Count | Should -Be 1
        }

        It 'records an inherited assignment under the parent that holds it' {
            $parent = [guid]::NewGuid().ToString()
            $null = Add-StandInObject -Path 'deviceAppManagement/mobileApps' -Name 'Company app' -Assignment @(Get-Target -GroupId $parent -Intent 'required')
            $target = Get-DirectTarget -GroupId $script:GroupId
            $target[$parent] = [pscustomobject]@{ Id = $parent; DisplayName = 'Parent'; Relationship = 'Inherited' }

            $result = Find-One -Path 'deviceAppManagement/mobileApps' -Target $target

            $result.Records[0].Relationship | Should -Be 'Inherited'
            $result.Records[0].AssignedGroup | Should -Be 'Parent'
            $result.Records[0].Intent | Should -Be 'required'
        }

        It 'records both an include and an exclude on one object' {
            $null = Add-StandInObject -Path 'deviceManagement/deviceConfigurations' -Name 'Both' -Assignment @(
                Get-Target -GroupId $script:GroupId
                Get-Target -GroupId $script:GroupId -Type 'exclusionGroupAssignmentTarget'
            )

            $result = Find-One -Path 'deviceManagement/deviceConfigurations' -Target (Get-DirectTarget -GroupId $script:GroupId)

            @($result.Records | ForEach-Object { $_.Assignment }) | Should -Be @('Include', 'Exclude')
        }

        It 'names a settings catalog policy, which calls it name' {
            $null = Add-StandInObject -Path 'deviceManagement/configurationPolicies' -Name 'Catalog' -NameProperty 'name' -Assignment @(Get-Target -GroupId $script:GroupId)

            $result = Find-One -Path 'deviceManagement/configurationPolicies' -Target (Get-DirectTarget -GroupId $script:GroupId)

            $result.Records[0].ObjectName | Should -Be 'Catalog'
        }

        It 'counts objects and matches on the coverage row' {
            $null = Add-StandInObject -Path 'deviceManagement/deviceConfigurations' -Name 'One' -Assignment @(Get-Target -GroupId $script:GroupId)
            $null = Add-StandInObject -Path 'deviceManagement/deviceConfigurations' -Name 'Two'

            $coverage = (Find-One -Path 'deviceManagement/deviceConfigurations' -Target (Get-DirectTarget -GroupId $script:GroupId)).Coverage

            $coverage.Status | Should -Be 'Complete'
            $coverage.Objects | Should -Be 2
            $coverage.Unread | Should -Be 0
            $coverage.Found | Should -Be 1
            $coverage.Detail | Should -BeNullOrEmpty
        }

        It 'calls an empty source complete' {
            $script:Tenant["$script:Beta/deviceManagement/intents"] = @()

            (Find-One -Path 'deviceManagement/intents' -Target (Get-DirectTarget -GroupId $script:GroupId)).Coverage.Status | Should -Be 'Complete'
        }
    }

    Context 'how each source is read' {

        It 'reads an object through its assignments path' {
            $id = Add-StandInObject -Path 'deviceManagement/deviceCompliancePolicies' -Name 'Compliance'

            $null = Find-One -Path 'deviceManagement/deviceCompliancePolicies' -Target (Get-DirectTarget -GroupId $script:GroupId)

            $script:Reads | Should -Contain "$script:Beta/deviceManagement/deviceCompliancePolicies/$id/assignments"
        }

        It 'reads a macOS script through $expand, and not through its assignments path' {
            $id = [guid]::NewGuid().ToString()
            $script:Tenant["$script:Beta/deviceManagement/deviceShellScripts"] = @([pscustomobject]@{ id = $id; displayName = 'Shell' })
            $script:Tenant["$script:Beta/deviceManagement/deviceShellScripts/$id`?`$expand=assignments"] = [pscustomobject]@{
                id = $id; assignments = @(Get-Target -GroupId $script:GroupId)
            }

            $result = Find-One -Path 'deviceManagement/deviceShellScripts' -Target (Get-DirectTarget -GroupId $script:GroupId)

            $result.Records.Count | Should -Be 1
            $script:Reads | Should -Not -Contain "$script:Beta/deviceManagement/deviceShellScripts/$id/assignments"
        }

        It 'reads a role assignment object by object, as members and scope groups' {
            $id = [guid]::NewGuid().ToString()
            $script:Tenant["$script:Beta/deviceManagement/roleAssignments"] = @([pscustomobject]@{ id = $id; displayName = 'Helpdesk' })
            $script:Tenant["$script:Beta/deviceManagement/roleAssignments/$id"] = [pscustomobject]@{
                id = $id; members = @($script:GroupId); resourceScopes = @($script:GroupId)
            }

            $result = Find-One -Path 'deviceManagement/roleAssignments' -Target (Get-DirectTarget -GroupId $script:GroupId)

            @($result.Records | ForEach-Object { $_.Assignment }) | Should -Be @('RoleMember', 'RoleScope')
        }
    }

    Context 'what cannot be read never passes for nothing assigned' {

        It 'marks a source it cannot list as Failed' {
            $script:Tenant["$script:Beta/deviceManagement/intents"] = Get-GraphFailure -StatusCode 400 -Message 'No OData route exists'

            $coverage = (Find-One -Path 'deviceManagement/intents' -Target (Get-DirectTarget -GroupId $script:GroupId)).Coverage

            $coverage.Status | Should -Be 'Failed'
            $coverage.Detail | Should -BeLike '*No OData route exists*'
        }

        It 'keeps going after one object fails, and marks the source Partial' {
            $null = Add-StandInObject -Path 'deviceManagement/deviceConfigurations' -Name 'Good' -Assignment @(Get-Target -GroupId $script:GroupId)
            $bad = Add-StandInObject -Path 'deviceManagement/deviceConfigurations' -Name 'Bad'
            $script:Tenant["$script:Beta/deviceManagement/deviceConfigurations/$bad/assignments"] = Get-GraphFailure -StatusCode 500
            $null = Add-StandInObject -Path 'deviceManagement/deviceConfigurations' -Name 'Also good' -Assignment @(Get-Target -GroupId $script:GroupId)

            $result = Find-One -Path 'deviceManagement/deviceConfigurations' -Target (Get-DirectTarget -GroupId $script:GroupId)

            $result.Coverage.Status | Should -Be 'Partial'
            $result.Coverage.Unread | Should -Be 1
            $result.Coverage.Detail | Should -BeLike '*Bad*HTTP 500*'
            $result.Records.Count | Should -Be 2
        }

        It 'marks a source Failed when no object could be read' {
            $bad = Add-StandInObject -Path 'deviceManagement/deviceConfigurations' -Name 'Bad'
            $script:Tenant["$script:Beta/deviceManagement/deviceConfigurations/$bad/assignments"] = Get-GraphFailure -StatusCode 500

            (Find-One -Path 'deviceManagement/deviceConfigurations' -Target (Get-DirectTarget -GroupId $script:GroupId)).Coverage.Status | Should -Be 'Failed'
        }

        It 'stops a source at the first 403, and counts the rest as unread' {
            $null = Add-StandInObject -Path 'deviceManagement/deviceConfigurations' -Name 'Good'
            $bad = Add-StandInObject -Path 'deviceManagement/deviceConfigurations' -Name 'Refused'
            $script:Tenant["$script:Beta/deviceManagement/deviceConfigurations/$bad/assignments"] = Get-GraphFailure -StatusCode 403
            $never = Add-StandInObject -Path 'deviceManagement/deviceConfigurations' -Name 'Never reached'

            $coverage = (Find-One -Path 'deviceManagement/deviceConfigurations' -Target (Get-DirectTarget -GroupId $script:GroupId)).Coverage

            $coverage.Status | Should -Be 'Partial'
            $coverage.Unread | Should -Be 2
            $script:Reads | Should -Not -Contain "$script:Beta/deviceManagement/deviceConfigurations/$never/assignments"
        }

        It 'caps the failures it quotes' {
            foreach ($number in 1..5) {
                $bad = Add-StandInObject -Path 'deviceManagement/deviceConfigurations' -Name "Bad $number"
                $script:Tenant["$script:Beta/deviceManagement/deviceConfigurations/$bad/assignments"] = Get-GraphFailure -StatusCode 500
            }

            $coverage = (Find-One -Path 'deviceManagement/deviceConfigurations' -Target (Get-DirectTarget -GroupId $script:GroupId)).Coverage

            $coverage.Unread | Should -Be 5
            @($coverage.Detail -split ' \| ').Count | Should -Be 3
        }

        It 'marks a source Partial for a target it cannot read' {
            $null = Add-StandInObject -Path 'deviceManagement/deviceConfigurations' -Name 'New kind' -Assignment @(Get-Target -Type 'someFutureAssignmentTarget')

            $coverage = (Find-One -Path 'deviceManagement/deviceConfigurations' -Target (Get-DirectTarget -GroupId $script:GroupId)).Coverage

            $coverage.Status | Should -Be 'Partial'
            $coverage.Detail | Should -BeLike '*1 assignment(s) name a target this script cannot read*'
        }

        It 'does not count all devices as a target it cannot read' {
            $null = Add-StandInObject -Path 'deviceManagement/deviceConfigurations' -Name 'Everyone' -Assignment @(Get-Target -Type 'allDevicesAssignmentTarget')

            (Find-One -Path 'deviceManagement/deviceConfigurations' -Target (Get-DirectTarget -GroupId $script:GroupId)).Coverage.Status | Should -Be 'Complete'
        }

        It 'marks a macOS script unread when the response has no assignments list' {
            $id = [guid]::NewGuid().ToString()
            $script:Tenant["$script:Beta/deviceManagement/deviceShellScripts"] = @([pscustomobject]@{ id = $id; displayName = 'Shell' })
            $script:Tenant["$script:Beta/deviceManagement/deviceShellScripts/$id`?`$expand=assignments"] = [pscustomobject]@{ id = $id }

            $coverage = (Find-One -Path 'deviceManagement/deviceShellScripts' -Target (Get-DirectTarget -GroupId $script:GroupId)).Coverage

            $coverage.Status | Should -Be 'Failed'
            $coverage.Detail | Should -BeLike "*no 'assignments' list*"
        }

        It 'marks a role assignment unread when the response has no members list' {
            $id = [guid]::NewGuid().ToString()
            $script:Tenant["$script:Beta/deviceManagement/roleAssignments"] = @([pscustomobject]@{ id = $id; displayName = 'Helpdesk' })
            $script:Tenant["$script:Beta/deviceManagement/roleAssignments/$id"] = [pscustomobject]@{ id = $id }

            $coverage = (Find-One -Path 'deviceManagement/roleAssignments' -Target (Get-DirectTarget -GroupId $script:GroupId)).Coverage

            $coverage.Status | Should -Be 'Failed'
            $coverage.Detail | Should -BeLike "*no 'members' list*"
        }
    }
}

Describe 'Resolve-AssignmentFilterName' {

    BeforeEach {
        Clear-StandInTenant
        $script:FilterUri ="$script:Beta/deviceManagement/assignmentFilters"
        $script:FilterId = [guid]::NewGuid().ToString()
    }

    It 'fills in the name of a filter' {
        $script:Tenant[$script:FilterUri] = @([pscustomobject]@{ id = $script:FilterId; displayName = 'Corporate only' })
        $record = [pscustomobject]@{ FilterId = $script:FilterId; FilterName = '' }

        Resolve-AssignmentFilterName -Record @($record) -BaseUri $script:Beta

        $record.FilterName | Should -Be 'Corporate only'
    }

    It 'reads nothing when no record has a filter' {
        Resolve-AssignmentFilterName -Record @([pscustomobject]@{ FilterId = ''; FilterName = '' }) -BaseUri $script:Beta

        $script:Reads.Count | Should -Be 0
    }

    It 'takes an empty list of records' {
        { Resolve-AssignmentFilterName -Record @() -BaseUri $script:Beta } | Should -Not -Throw
    }

    It 'warns and leaves the ID when the names cannot be read' {
        $script:Tenant[$script:FilterUri] = Get-GraphFailure -StatusCode 403
        $record = [pscustomobject]@{ FilterId = $script:FilterId; FilterName = '' }

        Resolve-AssignmentFilterName -Record @($record) -BaseUri $script:Beta -WarningVariable warned -WarningAction SilentlyContinue

        "$warned" | Should -BeLike '*give FilterId only*'
        $record.FilterName | Should -BeNullOrEmpty
        $record.FilterId | Should -Be $script:FilterId
    }

    It 'leaves the name blank for a filter that no longer exists' {
        $script:Tenant[$script:FilterUri] = @()
        $record = [pscustomobject]@{ FilterId = $script:FilterId; FilterName = '' }

        Resolve-AssignmentFilterName -Record @($record) -BaseUri $script:Beta

        $record.FilterName | Should -BeNullOrEmpty
    }
}

Describe 'The main block' {

    BeforeAll {
        # The body of the main block's try, without the catch around it, whose
        # exit would end the test run. The last try: the Graph module region
        # has one of its own.
        $trys = @($script:SyntaxTree.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.TryStatementAst] })
        $body = $trys[-1].Body.Extent.Text
        $script:MainBlock = [scriptblock]::Create($body.Substring(1, $body.Length - 2))

        $script:SignIns = [System.Collections.Generic.List[object]]::new()
        $script:AllCategories = @(Get-AssignmentSource | ForEach-Object { $_.Category } | Sort-Object -Unique)

        # Signs nothing in: the stand-in tenant needs no session.
        function Connect-GraphSession {
            param ($Scope, $TenantId, [switch]$UseDeviceCode)

            $script:SignIns.Add([pscustomobject]@{
                    Scope         = $Scope
                    TenantId      = $TenantId
                    UseDeviceCode = $UseDeviceCode.IsPresent
                    ReadsBefore   = $script:Reads.Count
                })
            $false
        }

        function Invoke-Main {
            # Runs the main block as the script would with these parameters,
            # and separates what it returns, warns and reports. Dot-sourced,
            # so the exit code it sets can be read back.
            param ([string]$Name = '', [string]$Id = '', [string[]]$Only = $script:AllCategories)

            $folder = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('n'))
            $null = New-Item -ItemType Directory -Path $folder

            # The main block reads the script's parameters and settings from
            # the scope that runs it.
            Set-Variable -Name 'GroupName' -Value $Name
            Set-Variable -Name 'GroupId' -Value $Id
            Set-Variable -Name 'Category' -Value $Only
            Set-Variable -Name 'OutputPath' -Value $folder
            Set-Variable -Name 'TenantId' -Value ''
            Set-Variable -Name 'UseDeviceCode' -Value ([switch]$false)
            Set-Variable -Name 'MaximumRetryCount' -Value 7
            Set-Variable -Name 'GraphBaseUri' -Value $script:V1
            Set-Variable -Name 'GraphBetaUri' -Value $script:Beta
            Set-Variable -Name 'ConnectionOpenedHere' -Value $false
            Set-Variable -Name 'ExitCode' -Value 0
            Set-Variable -Name 'InformationPreference' -Value 'Continue'
            Set-Variable -Name 'ErrorActionPreference' -Value 'Stop'

            $all =[System.Collections.Generic.List[object]]::new()
            $failure = $null
            try {
                . $script:MainBlock 3>&1 6>&1 | ForEach-Object { $all.Add($_) }
            }
            catch {
                $failure = $_.Exception.Message
            }

            [pscustomobject]@{
                Rows        = @($all | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] -and $_ -isnot [System.Management.Automation.InformationRecord] })
                Warnings    = @($all | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object { $_.Message })
                Information = @($all | Where-Object { $_ -is [System.Management.Automation.InformationRecord] } | ForEach-Object { [string]$_.MessageData })
                Failure     = $failure
                ExitCode    = Get-Variable -Name 'ExitCode' -ValueOnly
                Files       = @(Get-ChildItem -LiteralPath $folder -File | Sort-Object Name)
            }
        }

        function Get-CoverageRow {
            # The coverage report's row for a source, as written to the file.
            param ($Run, [string]$Source)

            $file = @($Run.Files | Where-Object { $_.Name -like '*-Coverage.csv' })[0]
            @(Import-Csv -LiteralPath $file.FullName | Where-Object { $_.Source -eq $Source })[0]
        }
    }

    BeforeEach {
        Clear-StandInTenant
        $script:SignIns.Clear()
        $script:Filter =[uri]::EscapeDataString("displayName eq 'Pilot'")
        $script:NameUri = "$script:V1/groups?`$filter=$script:Filter&`$select=id,displayName,createdDateTime&`$top=999"
        $script:IdUri = "$script:V1/groups/$($script:GroupId)?`$select=id,displayName,createdDateTime"
        $script:ParentUri = "$script:V1/groups/$($script:GroupId)/transitiveMemberOf?`$select=id,displayName"

        $script:Tenant[$script:NameUri] = @([pscustomobject]@{ id = $script:GroupId; displayName = 'Pilot' })
        $script:Tenant[$script:ParentUri] = @()
        foreach ($source in Get-AssignmentSource) { $script:Tenant["$script:Beta/$($source.Path)"] = @() }
    }

    It 'signs in once, with the scopes of the selected categories, before reading anything' {
        $null = Invoke-Main -Name 'Pilot' -Only 'Apps'

        $script:SignIns.Count | Should -Be 1
        $script:SignIns[0].ReadsBefore | Should -Be 0
        @($script:SignIns[0].Scope.Keys) | Should -Contain 'DeviceManagementApps.Read.All'
        @($script:SignIns[0].Scope.Keys) | Should -Not -Contain 'DeviceManagementRBAC.Read.All'
    }

    It 'gives every request the retry count it was given' {
        $null = Add-StandInObject -Path 'deviceManagement/deviceConfigurations' -Name 'Wi-Fi' -Assignment @(Get-Target -GroupId $script:GroupId)

        $null = Invoke-Main -Name 'Pilot'

        @($script:Attempts | Sort-Object -Unique) | Should -Be @(7)
    }

    It 'stops on a blank name before it signs in' {
        $run = Invoke-Main -Name '   '

        $run.Failure | Should -BeLike '*-GroupName is blank*'
        $script:SignIns.Count | Should -Be 0
    }

    It 'returns the records and writes both reports' {
        $null = Add-StandInObject -Path 'deviceManagement/deviceConfigurations' -Name 'Wi-Fi' -Assignment @(Get-Target -GroupId $script:GroupId)

        $run = Invoke-Main -Name 'Pilot'

        $run.Failure | Should -BeNullOrEmpty
        $run.ExitCode | Should -Be 0
        @($run.Rows).Count | Should -Be 1
        $run.Rows[0].ObjectName | Should -Be 'Wi-Fi'
        $run.Files.Count | Should -Be 2
        $run.Information | Should -Contain "Group 'Pilot': 1 direct and 0 inherited assignment(s)."

        $report = @($run.Files | Where-Object { $_.Name -notlike '*-Coverage.csv' })[0]
        (Import-Csv -LiteralPath $report.FullName).ObjectName | Should -Be 'Wi-Fi'
    }

    It 'searches every source by default' {
        $run = Invoke-Main -Name 'Pilot'

        foreach ($source in Get-AssignmentSource) {
            $script:Reads | Should -Contain "$script:Beta/$($source.Path)"
            (Get-CoverageRow -Run $run -Source $source.Label).Status | Should -Be 'Complete'
        }
    }

    It 'finds assignments of the groups it is nested in, as inherited' {
        $parent = [guid]::NewGuid().ToString()
        $script:Tenant[$script:ParentUri] = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.group'; id = $parent; displayName = 'All pilots' })
        $null = Add-StandInObject -Path 'deviceAppManagement/mobileApps' -Name 'Company app' -Assignment @(Get-Target -GroupId $parent -Intent 'required')
        $null = Add-StandInObject -Path 'deviceManagement/deviceConfigurations' -Name 'Wi-Fi' -Assignment @(Get-Target -GroupId $script:GroupId)

        $run = Invoke-Main -Name 'Pilot'

        $inherited = @($run.Rows | Where-Object { $_.Relationship -eq 'Inherited' })
        $inherited.Count | Should -Be 1
        $inherited[0].ObjectName | Should -Be 'Company app'
        $inherited[0].AssignedGroup | Should -Be 'All pilots'
        $run.Information | Should -Contain "Group 'Pilot' is nested in: All pilots."
        $run.Information | Should -Contain "Group 'Pilot': 1 direct and 1 inherited assignment(s)."
    }

    It 'fills in filter names on the records it returns' {
        $filterId = [guid]::NewGuid().ToString()
        $script:Tenant["$script:Beta/deviceManagement/assignmentFilters"] = @([pscustomobject]@{ id = $filterId; displayName = 'Corporate only' })
        $null = Add-StandInObject -Path 'deviceManagement/deviceConfigurations' -Name 'Wi-Fi' -Assignment @(Get-Target -GroupId $script:GroupId -FilterId $filterId -FilterMode 'include')

        $run = Invoke-Main -Name 'Pilot'

        $run.Rows[0].FilterName | Should -Be 'Corporate only'
        $run.Rows[0].FilterMode | Should -Be 'include'
    }

    It 'reports a search that found nothing, says what that does not prove, and exits 0' {
        $run = Invoke-Main -Name 'Pilot'

        $run.Failure | Should -BeNullOrEmpty
        $run.ExitCode | Should -Be 0
        @($run.Rows).Count | Should -Be 0
        @($run.Files).Count | Should -Be 1
        $run.Files[0].Name | Should -BeLike '*-Coverage.csv'
        @($run.Information | Where-Object { $_ -like '*does not prove the group is unused*' }).Count | Should -Be 1
    }

    It 'searches only the selected categories, and reports the rest as not searched' {
        $run = Invoke-Main -Name 'Pilot' -Only 'Apps'

        $script:Reads | Should -Contain "$script:Beta/deviceAppManagement/mobileApps"
        $script:Reads | Should -Not -Contain "$script:Beta/deviceManagement/deviceConfigurations"
        (Get-CoverageRow -Run $run -Source 'Device configuration profile').Status | Should -Be 'NotSearched'
        (Get-CoverageRow -Run $run -Source 'App').Status | Should -Be 'Complete'
        $run.ExitCode | Should -Be 0
    }

    It 'searches nothing when the name is ambiguous' {
        $script:Tenant[$script:NameUri] = @(
            [pscustomobject]@{ id = $script:GroupId; displayName = 'Pilot' }
            [pscustomobject]@{ id = [guid]::NewGuid().ToString(); displayName = 'Pilot' }
        )

        $run = Invoke-Main -Name 'Pilot'

        $run.Failure | Should -BeLike '*2 groups are named*'
        @($script:Reads | Where-Object { $_ -like "$script:Beta/*" }).Count | Should -Be 0
        @($run.Files).Count | Should -Be 0
    }

    It 'still searches for an object ID that no group has, with no parents to read' {
        $script:Tenant[$script:IdUri] = Get-GraphFailure -StatusCode 404
        $null = Add-StandInObject -Path 'deviceManagement/deviceConfigurations' -Name 'Orphaned' -Assignment @(Get-Target -GroupId $script:GroupId)

        $run = Invoke-Main -Id $script:GroupId

        @($run.Rows).Count | Should -Be 1
        $run.Rows[0].AssignedGroupId | Should -Be $script:GroupId
        $script:Reads | Should -Not -Contain $script:ParentUri
        (Get-CoverageRow -Run $run -Source 'Parent groups').Status | Should -Be 'NotApplicable'
        $run.ExitCode | Should -Be 0
    }

    It 'names the group by its ID in the summary when it has no name' {
        $script:Tenant[$script:IdUri] = Get-GraphFailure -StatusCode 404

        $run = Invoke-Main -Id $script:GroupId

        $run.Information | Should -Contain "Group '$($script:GroupId)': 0 direct and 0 inherited assignment(s)."
    }

    Context 'when part of the search cannot be read' {

        It 'returns what it found, warns, names the source, and sets exit code 2' {
            $null = Add-StandInObject -Path 'deviceManagement/deviceConfigurations' -Name 'Wi-Fi' -Assignment @(Get-Target -GroupId $script:GroupId)
            $script:Tenant["$script:Beta/deviceAppManagement/mobileApps"] = Get-GraphFailure -StatusCode 403

            $run = Invoke-Main -Name 'Pilot'

            $run.ExitCode | Should -Be 2
            @($run.Rows).Count | Should -Be 1
            $run.Warnings | Should -HaveCount 1
            $run.Warnings[0] | Should -BeLike '*may be incomplete*App (Failed)*'
            (Get-CoverageRow -Run $run -Source 'App').Detail | Should -BeLike '*HTTP 403*'
        }

        It 'does not offer an empty result as complete' {
            $script:Tenant["$script:Beta/deviceAppManagement/mobileApps"] = Get-GraphFailure -StatusCode 403

            $run = Invoke-Main -Name 'Pilot'

            @($run.Rows).Count | Should -Be 0
            $run.ExitCode | Should -Be 2
            $run.Warnings[0] | Should -BeLike '*may be incomplete*'
        }

        It 'treats a failed read of the parent groups the same way' {
            $script:Tenant[$script:ParentUri] = Get-GraphFailure -StatusCode 403
            $null = Add-StandInObject -Path 'deviceManagement/deviceConfigurations' -Name 'Wi-Fi' -Assignment @(Get-Target -GroupId $script:GroupId)

            $run = Invoke-Main -Name 'Pilot'

            $run.ExitCode | Should -Be 2
            @($run.Rows).Count | Should -Be 1
            $run.Warnings[0] | Should -BeLike '*Parent groups (Failed)*'
        }
    }

    It 'exits with the code the main block set, after the session is closed' {
        $last = $script:SyntaxTree.EndBlock.Statements[-1]

        $last.Extent.Text | Should -Be 'exit $ExitCode'
        $script:SyntaxTree.EndBlock.Statements[-2] | Should -BeOfType ([System.Management.Automation.Language.TryStatementAst])
    }
}

Describe 'The script, run as a file' -Skip:(-not $script:ModuleAvailable) {

    It 'exits 1 and gives the reason, not an error of its own, when it refuses a request' {
        # Started with -File in a child process, as a scheduled task would,
        # so that its exit ends that process and not the test run. The
        # request is refused before the script signs in, so nothing reaches
        # Graph. The text comes back without white space, because the host
        # wraps long errors.
        # Continue, not the caller's Stop: Windows PowerShell 5.1 turns the
        # child's error output into a terminating error under Stop, which
        # is what the Windows PowerShell step in CI sets, and the test would
        # end there instead of reading the exit code.
        $ErrorActionPreference = 'Continue'
        $output = @(& (Get-Process -Id $PID).Path -NoProfile -NonInteractive -File $script:ScriptPath -GroupName ' ' 2>&1)
        $exitCode = $LASTEXITCODE
        $text = (@($output | ForEach-Object { [string]$_ }) -join '') -replace '\s', ''

        $exitCode | Should -Be 1
        $text | Should -BeLike '*Scriptfailed:-GroupNameisblank.*'
    }
}

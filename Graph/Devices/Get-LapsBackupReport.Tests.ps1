# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/zenpachi-alt/endpoint-engineering

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

<#
.SYNOPSIS
    Pester tests for Get-LapsBackupReport.ps1: what it asks Graph for, and how
    it joins devices to LAPS backups and decides each device's status.

.DESCRIPTION
    The script's functions are loaded from its syntax tree, without running
    its main block, and Get-GraphCollection is replaced by a stand-in tenant
    held in memory. Nothing reaches Graph and no module is needed.

    The stand-in answers only the two collections the script is meant to
    read, and records every request, so a request for the credentials
    property, or for anything else, fails the tests.

    Identifier-shaped values are built at run time, so this file passes
    Tools/Test-SensitiveContent.ps1 like any other.

.EXAMPLE
    Invoke-Pester -Path .\Graph\Devices\Get-LapsBackupReport.Tests.ps1 -Output Detailed

.NOTES
    PowerShell    : 5.1 or 7.
    Graph scopes  : None. Nothing reaches a tenant.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : Pester 5.5.0 or later.
#>

BeforeAll {
    $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'Get-LapsBackupReport.ps1'

    # Every top-level function of the script, without the main block.
    $parseErrors = $null
    $syntaxTree = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$parseErrors)
    if ($parseErrors) { throw "Get-LapsBackupReport.ps1 does not parse: $($parseErrors[0].Message)" }
    foreach ($statement in $syntaxTree.EndBlock.Statements) {
        if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
            . ([scriptblock]::Create($statement.Extent.Text))
        }
    }

    $script:Base = 'https://graph.microsoft.com/v1.0'
    $script:BackupsUri = "$script:Base/directory/deviceLocalCredentials"
    $script:Reads = [System.Collections.Generic.List[object]]::new()

    # The moment the join tests compare rotation dates with.
    $script:Now = [datetime]::new(2026, 10, 15, 12, 0, 0, [DateTimeKind]::Utc)

    # Defined after the script's functions, so it replaces the helper. It
    # takes only the parameters the script passes, so a new one fails here.
    function Get-GraphCollection {
        param ([Parameter(Mandatory)][string]$Uri, [int]$MaximumAttempt)

        $script:Reads.Add([pscustomobject]@{ Uri = $Uri; MaximumAttempt = $MaximumAttempt })
        if ($script:Failures.ContainsKey($Uri)) { throw $script:Failures[$Uri] }

        $source = if ($Uri -like "$script:Base/devices?*") { $script:Devices }
        elseif ($Uri -ceq $script:BackupsUri) { $script:Backups }
        else { throw "The stand-in tenant has no collection at $Uri" }

        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in @($source)) { $items.Add($entry) }
        return , $items
    }

    function Get-StandInDevice {
        # A device as Graph v1.0 returns it with the script's $select.
        param (
            [string]$Name = 'DESKTOP-EXAMPLE',
            [string]$DeviceId = [guid]::NewGuid().ToString(),
            [string]$OperatingSystem = 'Windows',
            [object]$TrustType = 'AzureAd',
            [object]$LastSignIn = '2026-10-10T08:00:00Z',
            [object]$Enabled = $true
        )

        [pscustomobject]@{
            id                            = [guid]::NewGuid().ToString()
            deviceId                      = $DeviceId
            displayName                   = $Name
            operatingSystem               = $OperatingSystem
            operatingSystemVersion        = '10.0.26100.1'
            trustType                     = $TrustType
            accountEnabled                = $Enabled
            approximateLastSignInDateTime = $LastSignIn
        }
    }

    function Get-StandInBackup {
        # A deviceLocalCredentialInfo as the list returns it: never with the
        # credentials. By default it was backed up before $script:Now and is
        # due for rotation after it.
        param (
            [string]$DeviceId,
            [object]$LastBackup = '2026-10-01T10:00:00Z',
            [object]$Refresh = '2026-10-31T10:00:00Z'
        )

        [pscustomobject]@{
            id                 = $DeviceId
            deviceName         = 'DESKTOP-EXAMPLE'
            lastBackupDateTime = $LastBackup
            refreshDateTime    = $Refresh
        }
    }

    function Get-SingleRecord {
        # Runs the join at $script:Now and returns the only record it makes.
        param ([object[]]$Device, [object[]]$Backup = @())

        $records = @(ConvertTo-LapsReport -Device $Device -Backup $Backup -Now $script:Now)
        if ($records.Count -ne 1) { throw "Expected one record, got $($records.Count)." }
        $records[0]
    }
}

Describe 'Get-LapsReportData' {

    BeforeEach {
        $script:Reads.Clear()
        $script:Devices = @()
        $script:Backups = @()
        $script:Failures = @{}
    }

    It 'reads every device and every backup, and nothing else' {
        $script:Devices = @(Get-StandInDevice)
        $script:Backups = @(Get-StandInBackup -DeviceId $script:Devices[0].deviceId)

        $data = Get-LapsReportData -BaseUri $script:Base -MaximumAttempt 3

        $script:Reads | Should -HaveCount 2
        $script:Reads[0].Uri | Should -BeLike "$script:Base/devices?*"
        $script:Reads[1].Uri | Should -BeExactly $script:BackupsUri
        @($script:Reads | ForEach-Object MaximumAttempt) | Should -Be @(3, 3)
        $data.Devices.Count | Should -Be 1
        $data.Backups.Count | Should -Be 1
    }

    It 'asks for the device properties the report is made of, a full page at a time' {
        $null = Get-LapsReportData -BaseUri $script:Base

        $query = $script:Reads[0].Uri.Substring($script:Reads[0].Uri.IndexOf('?') + 1)
        $select = @(($query -split '&' | Where-Object { $_ -like '$select=*' }) -replace '^\$select=' -split ',')
        foreach ($property in 'id', 'deviceId', 'displayName', 'operatingSystem', 'operatingSystemVersion', 'trustType',
            'accountEnabled', 'approximateLastSignInDateTime') {
            $select | Should -Contain $property
        }
        @($query -split '&') | Should -Contain '$top=999'
    }

    It 'never asks for a password' {
        $null = Get-LapsReportData -BaseUri $script:Base

        # A password is asked for with $select=credentials. The list of
        # backups is read with no query options at all.
        $backupReads = @($script:Reads | Where-Object { $_.Uri -like '*deviceLocalCredentials*' })
        $backupReads | Should -HaveCount 1
        $backupReads[0].Uri | Should -BeExactly $script:BackupsUri
        $script:Reads | Where-Object { $_.Uri -match '[?&]\$(select|expand)=[^&]*credentials' } | Should -BeNullOrEmpty
    }

    It 'names the roles that may read LAPS details when the listing is refused' {
        $refused = [System.Exception]::new("HTTP 403 from GET $script:BackupsUri after 1 attempt(s): Authorization_RequestDenied")
        $refused.Data['StatusCode'] = 403
        $script:Failures[$script:BackupsUri] = $refused

        { Get-LapsReportData -BaseUri $script:Base } | Should -Throw -ExpectedMessage '*HTTP 403*Global Reader*Intune Administrator*Authorization_RequestDenied*'
    }

    It 'passes on any other failure unchanged' {
        $unavailable = [System.Exception]::new('HTTP 503 from GET after 5 attempt(s)')
        $unavailable.Data['StatusCode'] = 503
        $script:Failures[$script:BackupsUri] = $unavailable

        { Get-LapsReportData -BaseUri $script:Base } | Should -Throw -ExpectedMessage 'HTTP 503 from GET after 5 attempt(s)'
    }
}

Describe 'The report' {

    BeforeAll {
        # The body of the main block's try, without the catch around it,
        # whose exit would end the test run.
        $try = $syntaxTree.EndBlock.Statements[-1]
        if ($try -isnot [System.Management.Automation.Language.TryStatementAst]) { throw 'The main block is not a try statement.' }
        $body = $try.Body.Extent.Text
        $script:MainBlock = [scriptblock]::Create($body.Substring(1, $body.Length - 2))

        $script:SignIns = [System.Collections.Generic.List[object]]::new()
        $script:Scopes = [ordered]@{ 'Example.Read.All' = @('Example.ReadWrite.All') }

        # Signs nothing in: the stand-in tenant needs no session. Records what
        # it was asked for.
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

        function Invoke-Report {
            # Runs the main block as the script would with these parameters,
            # and separates what it returns, warns and says verbosely.
            param ([string[]]$StatusFilter, [string]$CsvFolder, [string]$Tenant = '', [switch]$DeviceCode)

            # The main block reads the script's parameters and settings from
            # the scope that runs it.
            Set-Variable -Name 'Status' -Value $StatusFilter
            Set-Variable -Name 'CsvPath' -Value $CsvFolder
            Set-Variable -Name 'TenantId' -Value $Tenant
            Set-Variable -Name 'UseDeviceCode' -Value $DeviceCode
            Set-Variable -Name 'MaximumRetryCount' -Value 5
            Set-Variable -Name 'GraphBaseUri' -Value $script:Base
            Set-Variable -Name 'RequiredScopes' -Value $script:Scopes
            Set-Variable -Name 'VerbosePreference' -Value 'Continue'
            Set-Variable -Name 'ErrorActionPreference' -Value 'Stop'

            $all = @(& $script:MainBlock 3>&1 4>&1)
            [pscustomobject]@{
                Rows     = @($all | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] -and $_ -isnot [System.Management.Automation.VerboseRecord] })
                Warnings = @($all | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object Message)
                Verbose  = @($all | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] } | ForEach-Object Message)
            }
        }
    }

    BeforeEach {
        $script:Reads.Clear()
        $script:SignIns.Clear()
        $script:Failures = @{}

        # The main block compares with the real clock, so these dates are
        # set from it.
        $ahead = [datetime]::UtcNow.AddDays(10).ToString('o')
        $behind = [datetime]::UtcNow.AddDays(-5).ToString('o')

        $backedUp = Get-StandInDevice -Name 'BACKEDUP'
        $overdue = Get-StandInDevice -Name 'OVERDUE'
        $none = Get-StandInDevice -Name 'NOBACKUP' -TrustType 'ServerAd'
        $personal = Get-StandInDevice -Name 'PERSONAL' -TrustType 'Workplace'
        $phone = Get-StandInDevice -Name 'PHONE' -OperatingSystem 'iOS'
        $script:Devices = @($backedUp, $overdue, $none, $personal, $phone)
        $script:Backups = @(
            Get-StandInBackup -DeviceId $backedUp.deviceId -Refresh $ahead
            Get-StandInBackup -DeviceId $overdue.deviceId -Refresh $behind
            # A backup of a device that is not in the report.
            Get-StandInBackup -DeviceId ([guid]::NewGuid().ToString()) -Refresh $ahead
        )
    }

    It 'signs in once, before reading, with its scopes and the tenant and sign-in method it was given' {
        $tenant = [guid]::NewGuid().ToString()

        $null = Invoke-Report -Tenant $tenant -DeviceCode

        $script:SignIns | Should -HaveCount 1
        $script:SignIns[0].ReadsBefore | Should -Be 0
        [object]::ReferenceEquals($script:SignIns[0].Scope, $script:Scopes) | Should -BeTrue
        $script:SignIns[0].TenantId | Should -Be $tenant
        $script:SignIns[0].UseDeviceCode | Should -BeTrue
    }

    It 'returns one row per joined Windows device' {
        $run = Invoke-Report

        @($run.Rows | ForEach-Object DeviceName | Sort-Object) | Should -Be @('BACKEDUP', 'NOBACKUP', 'OVERDUE')
        $run.Warnings | Should -BeNullOrEmpty
    }

    It 'keeps only the statuses -Status names' {
        $run = Invoke-Report -StatusFilter 'Overdue'

        @($run.Rows | ForEach-Object DeviceName) | Should -Be @('OVERDUE')
    }

    It 'counts each status, the Windows devices left out, and the backups of devices it does not report' {
        $run = Invoke-Report

        $run.Verbose | Should -Contain 'BackedUp: 1'
        $run.Verbose | Should -Contain 'Overdue: 1'
        $run.Verbose | Should -Contain 'NoBackup: 1'
        $run.Verbose | Should -Contain ('1 Windows device(s) are registered, or of a join type Entra ID does not name, ' +
            'and are not reported: only a joined device can back up to Entra ID.')
        $run.Verbose | Should -Contain '1 backup(s) belong to no device in the report, and are not reported.'
    }

    It 'warns when Entra ID holds no backup at all, and points at the tenant' {
        $script:Backups = @()

        $run = Invoke-Report

        $run.Rows | Should -HaveCount 3
        $run.Warnings | Should -HaveCount 1
        $run.Warnings[0] | Should -BeLike 'Entra ID holds no LAPS backup for any device.*Entra device settings*'
    }

    It 'warns when no device matches' {
        $script:Devices = @($script:Devices | Where-Object displayName -EQ 'BACKEDUP')

        $run = Invoke-Report -StatusFilter 'NoBackup'

        $run.Rows | Should -BeNullOrEmpty
        $run.Warnings | Should -Contain 'No devices matched. Check -Status, or whether the tenant has joined Windows devices.'
    }

    It 'says only that no device matched when the tenant has no joined Windows device' {
        $script:Devices = @($script:Devices | Where-Object displayName -EQ 'PHONE')
        $script:Backups = @()

        $run = Invoke-Report

        $run.Rows | Should -BeNullOrEmpty
        $run.Warnings | Should -Be @('No devices matched. Check -Status, or whether the tenant has joined Windows devices.')
    }

    It 'writes the rows it returns to a timestamped CSV, with no password column' {
        $folder = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('n'))
        $null = New-Item -ItemType Directory -Path $folder

        $run = Invoke-Report -CsvFolder $folder

        $file = @(Get-ChildItem -LiteralPath $folder -Filter 'LapsBackupReport-*.csv')
        $file | Should -HaveCount 1
        $csv = @(Import-Csv -LiteralPath $file[0].FullName)
        $csv | Should -HaveCount $run.Rows.Count
        @($csv[0].PSObject.Properties.Name) -match 'Password|Credential' | Should -BeNullOrEmpty
    }
}

Describe 'ConvertTo-JoinKind' {

    It 'reads <Value> as <Expected>' -ForEach @(
        @{ Value = 'AzureAd'; Expected = 'EntraJoined' }
        @{ Value = 'azuread'; Expected = 'EntraJoined' }
        @{ Value = 'ServerAd'; Expected = 'HybridJoined' }
        @{ Value = 'Workplace'; Expected = 'Registered' }
        @{ Value = 'unknownFutureValue'; Expected = 'Unknown' }
        @{ Value = ''; Expected = 'Unknown' }
        @{ Value = $null; Expected = 'Unknown' }
    ) {
        ConvertTo-JoinKind -TrustType $Value | Should -Be $Expected
    }
}

Describe 'ConvertTo-LapsReport' {

    Context 'status' {

        It 'is BackedUp when Entra ID holds a backup whose rotation is still ahead' {
            $device = Get-StandInDevice

            $record = Get-SingleRecord -Device $device -Backup (Get-StandInBackup -DeviceId $device.deviceId)

            $record.Status | Should -Be 'BackedUp'
            $record.DaysOverdue | Should -BeNullOrEmpty
        }

        It 'is BackedUp when the rotation is due at this very moment' {
            $device = Get-StandInDevice

            $record = Get-SingleRecord -Device $device -Backup (Get-StandInBackup -DeviceId $device.deviceId -Refresh $script:Now)

            $record.Status | Should -Be 'BackedUp'
        }

        It 'is BackedUp when the backup carries no rotation date' {
            $device = Get-StandInDevice

            $record = Get-SingleRecord -Device $device -Backup (Get-StandInBackup -DeviceId $device.deviceId -Refresh $null)

            $record.Status | Should -Be 'BackedUp'
            $record.NextRotationDateTime | Should -BeNullOrEmpty
            $record.LastBackupDateTime | Should -Not -BeNullOrEmpty
        }

        It 'is Overdue when the rotation date has passed by <Case>' -ForEach @(
            @{ Case = 'an hour'; Refresh = '2026-10-15T11:00:00Z'; Days = 0 }
            @{ Case = 'ten days and two hours'; Refresh = '2026-10-05T10:00:00Z'; Days = 10 }
        ) {
            $device = Get-StandInDevice

            $record = Get-SingleRecord -Device $device -Backup (Get-StandInBackup -DeviceId $device.deviceId -Refresh $Refresh)

            $record.Status | Should -Be 'Overdue'
            $record.DaysOverdue | Should -Be $Days
        }

        It 'is NoBackup for a joined device Entra ID holds nothing for' {
            $record = Get-SingleRecord -Device (Get-StandInDevice)

            $record.Status | Should -Be 'NoBackup'
            $record.LastBackupDateTime | Should -BeNullOrEmpty
            $record.NextRotationDateTime | Should -BeNullOrEmpty
            $record.DaysOverdue | Should -BeNullOrEmpty
        }

        It 'is NoBackup for a device with no Entra device ID, whatever the backups say' {
            $record = Get-SingleRecord -Device (Get-StandInDevice -DeviceId '') -Backup (Get-StandInBackup -DeviceId '')

            $record.Status | Should -Be 'NoBackup'
        }
    }

    Context 'joining devices to backups' {

        It 'matches the Entra device ID without regard to case' {
            $device = Get-StandInDevice
            $device.deviceId = $device.deviceId.ToUpperInvariant()

            $record = Get-SingleRecord -Device $device -Backup (Get-StandInBackup -DeviceId $device.deviceId.ToLowerInvariant())

            $record.Status | Should -Be 'BackedUp'
        }

        It 'gives each device only its own backup' {
            $mine = Get-StandInDevice -Name 'MINE'
            $other = Get-StandInDevice -Name 'OTHER'

            $records = @(ConvertTo-LapsReport -Device @($mine, $other) -Backup @(Get-StandInBackup -DeviceId $other.deviceId) -Now $script:Now)

            ($records | Where-Object DeviceName -EQ 'MINE').Status | Should -Be 'NoBackup'
            ($records | Where-Object DeviceName -EQ 'OTHER').Status | Should -Be 'BackedUp'
        }

        It 'keeps the backup made last when Entra ID lists two for a device, the later one <Case>' -ForEach @(
            @{ Case = 'first'; LaterFirst = $true }
            @{ Case = 'second'; LaterFirst = $false }
        ) {
            $device = Get-StandInDevice
            $earlier = Get-StandInBackup -DeviceId $device.deviceId -LastBackup '2026-09-01T10:00:00Z' -Refresh '2026-10-01T10:00:00Z'
            $later = Get-StandInBackup -DeviceId $device.deviceId -LastBackup '2026-10-10T10:00:00Z' -Refresh '2026-11-09T10:00:00Z'
            $backups = if ($LaterFirst) { @($later, $earlier) } else { @($earlier, $later) }

            $record = Get-SingleRecord -Device $device -Backup $backups

            $record.Status | Should -Be 'BackedUp'
            $record.LastBackupDateTime | Should -Be ([datetime]::new(2026, 10, 10, 10, 0, 0, [DateTimeKind]::Utc))
        }

        It 'reports only Windows devices' {
            $devices = @((Get-StandInDevice -Name 'PC'), (Get-StandInDevice -Name 'PHONE' -OperatingSystem 'iOS'), (Get-StandInDevice -Name 'MAC' -OperatingSystem 'macOS'))

            $records = @(ConvertTo-LapsReport -Device $devices -Backup @() -Now $script:Now)

            @($records | ForEach-Object DeviceName) | Should -Be @('PC')
        }

        It 'reports a device that is <Case>, as <Expected>' -ForEach @(
            @{ Case = 'Entra joined'; TrustType = 'AzureAd'; Expected = 'EntraJoined' }
            @{ Case = 'hybrid joined'; TrustType = 'ServerAd'; Expected = 'HybridJoined' }
        ) {
            $record = Get-SingleRecord -Device (Get-StandInDevice -TrustType $TrustType)

            $record.JoinType | Should -Be $Expected
        }

        It 'leaves out a device that is <Case>, even when a backup carries its ID' -ForEach @(
            @{ Case = 'registered'; TrustType = 'Workplace' }
            @{ Case = 'of no named join type'; TrustType = $null }
        ) {
            $device = Get-StandInDevice -TrustType $TrustType

            $records = @(ConvertTo-LapsReport -Device @($device) -Backup @(Get-StandInBackup -DeviceId $device.deviceId) -Now $script:Now)

            $records | Should -HaveCount 0
        }

        It 'returns nothing for an empty tenant' {
            @(ConvertTo-LapsReport -Device @() -Backup @()) | Should -HaveCount 0
        }
    }

    Context 'the record' {

        It 'gives the backup and rotation dates in UTC, from text or from a DateTime' {
            $device = Get-StandInDevice
            $backup = Get-StandInBackup -DeviceId $device.deviceId -LastBackup '2026-10-01T12:00:00+02:00' `
                -Refresh ([datetime]::new(2026, 10, 31, 10, 0, 0, [DateTimeKind]::Utc))

            $record = Get-SingleRecord -Device $device -Backup $backup

            $record.LastBackupDateTime | Should -Be ([datetime]::new(2026, 10, 1, 10, 0, 0, [DateTimeKind]::Utc))
            $record.LastBackupDateTime.Kind | Should -Be 'Utc'
            $record.NextRotationDateTime | Should -Be ([datetime]::new(2026, 10, 31, 10, 0, 0, [DateTimeKind]::Utc))
            $record.NextRotationDateTime.Kind | Should -Be 'Utc'
        }

        It 'counts whole days since the last sign-in, and leaves them empty for a device that never signed in' {
            $recent = Get-StandInDevice -Name 'RECENT' -LastSignIn $script:Now.AddDays(-3).AddHours(-5).ToString('o')
            $never = Get-StandInDevice -Name 'NEVER' -LastSignIn $null

            $records = @(ConvertTo-LapsReport -Device @($recent, $never) -Backup @() -Now $script:Now)

            ($records | Where-Object DeviceName -EQ 'RECENT').DaysSinceLastSignIn | Should -Be 3
            ($records | Where-Object DeviceName -EQ 'NEVER').DaysSinceLastSignIn | Should -BeNullOrEmpty
            ($records | Where-Object DeviceName -EQ 'NEVER').LastSignInDateTime | Should -BeNullOrEmpty
        }

        It 'carries what identifies the device and says whether it is enabled' {
            $device = Get-StandInDevice -Name 'PC' -Enabled $false

            $record = Get-SingleRecord -Device $device

            $record.DeviceName | Should -Be 'PC'
            $record.AccountEnabled | Should -BeFalse
            $record.OperatingSystemVersion | Should -Be '10.0.26100.1'
            $record.EntraDeviceId | Should -Be $device.deviceId
            $record.ObjectId | Should -Be $device.id
        }

        It 'has no property that could hold a password' {
            $device = Get-StandInDevice

            $record = Get-SingleRecord -Device $device -Backup (Get-StandInBackup -DeviceId $device.deviceId)

            @($record.PSObject.Properties.Name) -match 'Password|Credential' | Should -BeNullOrEmpty
        }
    }
}

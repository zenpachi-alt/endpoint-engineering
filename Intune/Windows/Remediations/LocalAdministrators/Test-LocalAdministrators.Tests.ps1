# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/zenpachi-alt/endpoint-engineering

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

<#
.SYNOPSIS
    Pester tests for Test-LocalAdministrators.ps1: what each member is taken
    for, which members are expected, and the exit code and output line the
    script reports for each situation.

.DESCRIPTION
    Get-MemberKind, Get-AdministratorsVerdict and ConvertTo-AllowList read no
    state, so their rules are checked directly. Runs anywhere.

    The script itself runs as the Intune management extension runs it, in
    Windows PowerShell 5.1 with -File, with the two functions that touch the
    device - reading the group and reading the machine SID - replaced by
    stand-ins that describe a device. Windows only.

    Every SID here is made up: the digits are placeholders, and no test reads
    the group of the machine it runs on.

.EXAMPLE
    Invoke-Pester -Path .\Intune\Windows\Remediations\LocalAdministrators -Output Detailed

.NOTES
    PowerShell    : 5.1 or 7. The script under test always runs in Windows
                    PowerShell 5.1, whichever host runs Pester.
    Context       : Any user.
    Graph scopes  : None.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : Pester 5.5.0 or later.
#>

BeforeDiscovery {
    $script:OnWindows = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
}

BeforeAll {
    $script:ScriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'Test-LocalAdministrators.ps1'

    #region Remediation test harness 1.0.0 - canonical copy in Templates/Remediation/ExampleSetting.Tests.ps1
    # Paste this region unchanged into the BeforeAll block of a remediation
    # package's tests. Templates/Remediation/README.md describes how to use it.

    function ConvertTo-StubbedScript {
        <#
            Writes a copy of a script in which the named functions are replaced
            by stand-ins, and returns the copy's path. The parameters, the main
            block and every other function run as written.

            A stand-in keeps the original's attributes and parameters, records
            each call in $Fake.Calls, and then runs its body from -Stub. A body
            of $null returns the next result queued for the function in
            $Fake.Results. $Fake is the device the test passed to
            Invoke-RemediationScript, and changes a stand-in makes to it are
            returned to the test.
        #>
        param (
            [Parameter(Mandatory)]
            [string]$Path,

            [Parameter(Mandatory)]
            [System.Collections.IDictionary]$Stub,

            [Parameter(Mandatory)]
            [string]$Destination
        )

        $parseErrors = $null
        $syntaxTree = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$parseErrors)
        if ($parseErrors) { throw "$Path does not parse: $($parseErrors[0].Message)" }
        if ($null -eq $syntaxTree.ParamBlock) { throw "$Path has no param block for the stand-ins to follow." }

        $text = $syntaxTree.Extent.Text
        if ($text -match '\$Fake\b') { throw "$Path already uses `$Fake, which the stand-ins need." }

        $functions = @($syntaxTree.FindAll({ param ($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false))
        $edits = New-Object -TypeName System.Collections.Generic.List[object]

        foreach ($name in $Stub.Keys) {
            $matching = @($functions | Where-Object { $_.Name -eq $name })
            if ($matching.Count -ne 1) {
                throw "$Path defines $($matching.Count) functions named '$name'; a stand-in needs exactly one."
            }

            $original = $matching[0]
            $paramBlock = $original.Body.ParamBlock
            $signature = if ($null -eq $paramBlock) {
                "[CmdletBinding()]`nparam ()"
            }
            else {
                (@($paramBlock.Attributes | ForEach-Object { $_.Extent.Text }) + $paramBlock.Extent.Text) -join "`n"
            }

            $body = if ($null -eq $Stub[$name]) { "Get-FakeResult -Name '$name'" } else { $Stub[$name].ToString() }

            $edits.Add([pscustomobject]@{
                    Start = $original.Extent.StartOffset
                    End   = $original.Extent.EndOffset
                    Text  = "function $name {`n$signature`nAdd-FakeCall -Name '$name' -Parameter `$PSBoundParameters`ntry {`n$body`n}`nfinally {`nSave-Fake`n}`n}"
                })
        }

        # The device the test describes, and the functions the stand-ins use,
        # placed straight after the param block so the stand-ins can use them.
        $prelude = @'


# ---- Inserted by ConvertTo-StubbedScript: this copy is for tests only. ----
$Fake = Import-Clixml -LiteralPath $env:REMEDIATION_TEST_FAKE

function Save-Fake {
    $Fake | Export-Clixml -LiteralPath $env:REMEDIATION_TEST_FAKE -Depth 5
}

function Add-FakeCall {
    param ([string]$Name, [System.Collections.IDictionary]$Parameter)

    $arguments = @{}
    foreach ($key in $Parameter.Keys) { $arguments[$key] = [string]$Parameter[$key] }
    $Fake.Calls = @($Fake.Calls) + @{ Name = $Name; Parameters = $arguments }
    Save-Fake
}

function Get-FakeResult {
    param ([string]$Name)

    if (-not $Fake.Results.ContainsKey($Name)) { throw "The test queued no result for $Name." }
    $queue = @($Fake.Results[$Name])
    $made = @($Fake.Calls | Where-Object { $_.Name -eq $Name }).Count
    $next = $queue[[Math]::Min($made, $queue.Count) - 1]
    if ($next -is [System.Collections.IDictionary] -and $next.Contains('Throw')) { throw [string]$next['Throw'] }
    return $next
}
# ---- End of inserted code. ----
'@
        $edits.Add([pscustomobject]@{
                Start = $syntaxTree.ParamBlock.Extent.EndOffset
                End   = $syntaxTree.ParamBlock.Extent.EndOffset
                Text  = $prelude
            })

        # From the end backwards, so every offset still points where it did.
        foreach ($edit in @($edits | Sort-Object -Property Start -Descending)) {
            $text = $text.Substring(0, $edit.Start) + $edit.Text + $text.Substring($edit.End)
        }

        # Written without a BOM, ASCII-only, like the script it came from.
        [System.IO.File]::WriteAllText($Destination, $text, (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false))
        return $Destination
    }

    function Invoke-RemediationScript {
        <#
            Runs a script as the Intune management extension does and returns
            ExitCode, Output (the non-empty STDOUT lines), Error (STDERR, with
            the console's line wrapping undone), and
            Fake: the device after the run, with every stand-in call in Calls
            as Name and Parameters. -Fake is needed for a stubbed script, where
            Results holds what each stand-in returns by function name: one
            value, or a list used in turn whose last item repeats. A value of
            @{ Throw = '<message>' } makes the stand-in throw instead.
        #>
        param (
            [Parameter(Mandatory)]
            [string]$Path,

            [Parameter()]
            [string[]]$ArgumentList = @(),

            [Parameter()]
            [hashtable]$Fake,

            [Parameter()]
            [switch]$Use32BitHost,

            [Parameter()]
            [int]$TimeoutSeconds = 120
        )

        # A 32-bit process sees SysWOW64 as System32; Sysnative reaches the
        # real one.
        $folder = if ($Use32BitHost) { 'SysWOW64' }
        elseif ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { 'Sysnative' }
        else { 'System32' }
        $executable = Join-Path -Path $env:SystemRoot -ChildPath "$folder\WindowsPowerShell\v1.0\powershell.exe"

        $arguments = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $Path) + $ArgumentList
        $quoted = foreach ($argument in $arguments) {
            if ($argument -notmatch '[\s"]') { $argument; continue }
            # A backslash before the closing quote would escape it.
            '"' + (($argument -replace '"', '\"') -replace '(\\+)$', '$1$1') + '"'
        }

        $info = New-Object -TypeName System.Diagnostics.ProcessStartInfo
        $info.FileName = $executable
        $info.Arguments = $quoted -join ' '
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true

        $fakePath = $null
        if ($Fake) {
            $state = @{ Calls = @(); Results = @{} }
            foreach ($key in $Fake.Keys) { $state[$key] = $Fake[$key] }
            $fakePath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('RemediationFake-' + [guid]::NewGuid().ToString('n') + '.xml')
            $state | Export-Clixml -LiteralPath $fakePath -Depth 5
            $info.EnvironmentVariables['REMEDIATION_TEST_FAKE'] = $fakePath
        }

        try {
            $process = [System.Diagnostics.Process]::Start($info)
            $outputTask = $process.StandardOutput.ReadToEndAsync()
            $errorTask = $process.StandardError.ReadToEndAsync()

            if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
                $process.Kill()
                throw "$Path did not finish within $TimeoutSeconds seconds."
            }
            $process.WaitForExit()

            [pscustomobject]@{
                ExitCode = $process.ExitCode
                Output   = @($outputTask.Result -split '\r?\n' | Where-Object { $_ -ne '' })
                Error    = ($errorTask.Result -replace '\s+', ' ').Trim()
                Fake     =if ($fakePath) { Import-Clixml -LiteralPath $fakePath } else { $null }
            }
        }
        finally {
            if ($fakePath -and (Test-Path -LiteralPath $fakePath)) { Remove-Item -LiteralPath $fakePath -Force }
        }
    }

    function Get-FakeCall {
        # The stand-in calls a run made, in order, optionally of one function.
        # PowerShell unrolls a single call into the hashtable itself, so index
        # the result as @(Get-FakeCall ...)[0].
        param ([Parameter(Mandatory)][object]$Run, [string]$Name)

        @($Run.Fake.Calls | Where-Object { -not $Name -or $_.Name -eq $Name })
    }
    #endregion Remediation test harness

    # The script's functions that read no state, for the tests that call them
    # directly. The two that touch the device are left out.
    $parseErrors = $null
    $syntaxTree = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$parseErrors)
    if ($parseErrors) { throw "Test-LocalAdministrators.ps1 does not parse: $($parseErrors[0].Message)" }
    foreach ($statement in $syntaxTree.EndBlock.Statements) {
        if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $statement.Name -in @('ConvertTo-AllowList', 'ConvertTo-SidText', 'Get-MemberKind', 'Get-AdministratorsVerdict')) {
            . ([scriptblock]::Create($statement.Extent.Text))
        }
    }

    $script:LogDirectory = Join-Path -Path $TestDrive -ChildPath 'Logs'
    $script:LogArguments = @('-LogDirectory', $script:LogDirectory)

    # Made-up SIDs. The device's own accounts start with $script:Machine.
    $script:Machine = 'S-1-5-21-1111111111-2222222222-3333333333'
    $script:Domain = 'S-1-5-21-1000000001-1000000002-1000000003'
    $script:EntraRole = 'S-1-12-1-1111111111-2222222222-3333333333-4000000000'
    $script:EntraUser = 'S-1-12-1-1000000005-1000000006-1000000007-1000000008'

    function Get-FakeMember {
        # A member as Get-AdministratorsGroupMember returns it. A hashtable,
        # so it survives the trip to the script under test.
        param ([Parameter(Mandatory)][string]$Sid, [string]$Name = '')

        @{ Sid = $Sid; Name = $Name }
    }

    $script:BuiltIn = Get-FakeMember -Sid "$script:Machine-500" -Name 'CONTOSO-PC\Administrator'
    $script:LocalUser = Get-FakeMember -Sid "$script:Machine-1001" -Name 'CONTOSO-PC\helpdesk'
    $script:LapsAccount = Get-FakeMember -Sid "$script:Machine-1002" -Name 'CONTOSO-PC\LapsAdmin'
    $script:Role = Get-FakeMember -Sid $script:EntraRole
    $script:User = Get-FakeMember -Sid $script:EntraUser -Name 'AzureAD\AdeleVance'
    $script:DomainAdmins = Get-FakeMember -Sid "$script:Domain-512" -Name 'CONTOSO\Domain Admins'
    $script:DomainGroup = Get-FakeMember -Sid "$script:Domain-1105" -Name 'CONTOSO\Workstation Admins'
    $script:Everyone = Get-FakeMember -Sid 'S-1-1-0' -Name 'Everyone'

    function Get-FakeDevice {
        # A device whose group holds only the built-in Administrator, changed
        # by the arguments.
        param (
            [object[]]$Member = @($script:BuiltIn),
            [string]$MachineSid = $script:Machine,
            [switch]$GroupUnreadable
        )

        @{
            Members         = @($Member)
            MachineSid      = $MachineSid
            GroupUnreadable = $GroupUnreadable.IsPresent
        }
    }

    function Get-Verdict {
        # The verdict in Detect mode with an empty allow-list, changed by the
        # arguments.
        param (
            [object[]]$Member = @(),
            [string[]]$AllowedSid = @(),
            [string[]]$AllowedLocalAccountName = @(),
            [string]$Mode = 'Detect'
        )

        Get-AdministratorsVerdict -Member $Member -MachineSid $script:Machine -AllowedSid $AllowedSid `
            -AllowedLocalAccountName $AllowedLocalAccountName -Mode $Mode
    }
}

Describe 'Get-MemberKind' {

    It 'takes <Case> for <Expected>' -ForEach @(
        @{ Case = 'the device account with RID 500'; Sid = 'S-1-5-21-1111111111-2222222222-3333333333-500'; Expected = 'BuiltInAdministrator' }
        @{ Case = 'another account of the device'; Sid = 'S-1-5-21-1111111111-2222222222-3333333333-1001'; Expected = 'LocalAccount' }
        @{ Case = 'an Entra SID'; Sid = 'S-1-12-1-1111111111-2222222222-3333333333-4000000000'; Expected = 'EntraPrincipal' }
        @{ Case = 'RID 512 of a domain'; Sid = 'S-1-5-21-1000000001-1000000002-1000000003-512'; Expected = 'DomainAdmins' }
        @{ Case = 'another account of a domain'; Sid = 'S-1-5-21-1000000001-1000000002-1000000003-1105'; Expected = 'DomainPrincipal' }
        @{ Case = 'RID 500 of a domain, which is not this device''s'; Sid = 'S-1-5-21-1000000001-1000000002-1000000003-500'; Expected = 'DomainPrincipal' }
        @{ Case = 'Everyone'; Sid = 'S-1-1-0'; Expected = 'Other' }
        @{ Case = 'Authenticated Users'; Sid = 'S-1-5-11'; Expected = 'Other' }
    ) {
        Get-MemberKind -Sid $Sid -MachineSid $script:Machine | Should -Be $Expected
    }

    It 'does not take a device whose SID only starts like this one for this device' {
        # 333333333 and 3333333333 share a prefix as text.
        Get-MemberKind -Sid 'S-1-5-21-1111111111-2222222222-3333333333-500' -MachineSid 'S-1-5-21-1111111111-2222222222-333333333' |
            Should -Be 'DomainPrincipal'
    }
}

Describe 'ConvertTo-AllowList' {

    It 'returns <Case> as <Count> entries' -ForEach @(
        @{ Case = 'an array'; Value = @('a', 'b'); Count = 2 }
        @{ Case = 'one comma-separated string, as -File passes it'; Value = @('a,b,c'); Count = 3 }
        @{ Case = 'a mix of both'; Value = @('a,b', 'c'); Count = 3 }
        @{ Case = 'entries with spaces around them'; Value = @(' a , b '); Count = 2 }
        @{ Case = 'blanks and stray commas'; Value = @('', ' ', 'a,,'); Count = 1 }
        @{ Case = 'an empty list'; Value = @(); Count = 0 }
        @{ Case = 'nothing'; Value = $null; Count = 0 }
    ) {
        $entries = @(ConvertTo-AllowList -Value $Value)

        $entries | Should -HaveCount $Count
        $entries | Where-Object { $_ -ne $_.Trim() -or -not $_ } | Should -BeNullOrEmpty
    }
}

Describe 'ConvertTo-SidText' -Skip:(-not $script:OnWindows) {

    It 'returns a SID as Windows writes it' {
        ConvertTo-SidText -Value 's-1-5-21-1111111111-2222222222-3333333333-1001' | Should -BeExactly 'S-1-5-21-1111111111-2222222222-3333333333-1001'
    }

    It 'throws on text that is not a SID, naming it' {
        { ConvertTo-SidText -Value 'CONTOSO\helpdesk' } | Should -Throw -ExpectedMessage "'CONTOSO\helpdesk' in AllowedSid is not a SID.*"
    }

    It 'throws on a number too large for a SID, which Windows would read as another SID' {
        # 4294967295 is the largest number a SID can hold. Windows reads
        # anything above it as that, without an error.
        { ConvertTo-SidText -Value 'S-1-12-1-1111111111-2222222222-3333333333-5000000000' } |
            Should -Throw -ExpectedMessage '*is not a SID Windows can hold: it reads it as ''S-1-12-1-1111111111-2222222222-3333333333-4294967295''*'
    }
}

Describe 'Get-AdministratorsVerdict' {

    Context 'what is expected without an allow-list' {

        It 'expects the built-in Administrator and Domain Admins' {
            $verdict = Get-Verdict -Member @($script:BuiltIn, $script:DomainAdmins)

            $verdict.Token | Should -Be 'Expected'
            $verdict.ExitCode | Should -Be 0
            $verdict.Detail | Should -Be 'all 2 member(s) are built in or allowed.'
        }

        It 'does not expect <Case>' -ForEach @(
            @{ Case = 'another local account'; Member = 'LocalUser' }
            @{ Case = 'an Entra role or group, which has no name'; Member = 'Role' }
            @{ Case = 'an Entra user'; Member = 'User' }
            @{ Case = 'a domain group'; Member = 'DomainGroup' }
            @{ Case = 'a well-known group'; Member = 'Everyone' }
        ) {
            $unexpected = Get-Variable -Name $Member -Scope Script -ValueOnly

            $verdict = Get-Verdict -Member @($script:BuiltIn, $unexpected)

            $verdict.Token | Should -Be 'Unexpected'
            $verdict.ExitCode | Should -Be 1
            $verdict.Detail | Should -BeLike "1 of 2 member(s) are not allowed: *$($unexpected.Sid)*"
        }

        It 'expects an empty group' {
            $verdict = Get-Verdict -Member @()

            $verdict.Token | Should -Be 'Expected'
            $verdict.ExitCode | Should -Be 0
            $verdict.Detail | Should -Be 'the group has no members.'
        }
    }

    Context 'the allow-list of SIDs' {

        It 'expects <Case> once its SID is allowed' -ForEach @(
            @{ Case = 'an Entra role'; Member = 'Role' }
            @{ Case = 'an Entra user'; Member = 'User' }
            @{ Case = 'a domain group'; Member = 'DomainGroup' }
            @{ Case = 'a well-known group'; Member = 'Everyone' }
            @{ Case = 'a local account'; Member = 'LocalUser' }
        ) {
            $allowed = Get-Variable -Name $Member -Scope Script -ValueOnly

            $verdict = Get-Verdict -Member @($script:BuiltIn, $allowed) -AllowedSid $allowed.Sid

            $verdict.Token | Should -Be 'Expected'
            @($verdict.Members | Where-Object Sid -EQ $allowed.Sid)[0].Reason | Should -Be 'SID allowed'
        }

        It 'compares SIDs without regard to case' {
            $verdict = Get-Verdict -Member @($script:Role) -AllowedSid $script:EntraRole.ToLowerInvariant()

            $verdict.Token | Should -Be 'Expected'
        }

        It 'allows only the SIDs it names' {
            $verdict = Get-Verdict -Member @($script:Role, $script:User) -AllowedSid $script:EntraRole

            $verdict.Token | Should -Be 'Unexpected'
            $verdict.Detail | Should -BeLike "1 of 2 member(s) are not allowed: AzureAD\AdeleVance ($script:EntraUser, EntraPrincipal)."
        }
    }

    Context 'the allow-list of local account names' {

        It 'expects a local account whose name is allowed, without regard to case' {
            $verdict = Get-Verdict -Member @($script:BuiltIn, $script:LapsAccount) -AllowedLocalAccountName 'lapsadmin'

            $verdict.Token | Should -Be 'Expected'
            @($verdict.Members | Where-Object Sid -EQ $script:LapsAccount.Sid)[0].Reason | Should -Be 'name allowed'
        }

        It 'does not expect <Case> of an allowed name' -ForEach @(
            @{ Case = 'a domain account'; Sid = 'S-1-5-21-1000000001-1000000002-1000000003-1200'; Name = 'CONTOSO\LapsAdmin' }
            @{ Case = 'an Entra account'; Sid = 'S-1-12-1-1000000005-1000000006-1000000007-1000000008'; Name = 'AzureAD\LapsAdmin' }
        ) {
            # A name is trusted only for an account of this device: anyone
            # with a directory account could be given the same name.
            $verdict = Get-Verdict -Member @(Get-FakeMember -Sid $Sid -Name $Name) -AllowedLocalAccountName 'LapsAdmin'

            $verdict.Token | Should -Be 'Unexpected'
        }

        It 'does not expect a local account that has no name on the device' {
            $verdict = Get-Verdict -Member @(Get-FakeMember -Sid $script:LapsAccount.Sid) -AllowedLocalAccountName 'LapsAdmin'

            $verdict.Token | Should -Be 'Unexpected'
        }
    }

    Context 'Inventory mode' {

        It 'never flags the device, and lists the members not allowed first' {
            $verdict = Get-Verdict -Mode Inventory -Member @($script:BuiltIn, $script:Role, $script:LocalUser)

            $verdict.Token | Should -Be 'Inventory'
            $verdict.ExitCode | Should -Be 0
            $verdict.Detail | Should -Be ("3 member(s). Not allowed: $script:EntraRole (EntraPrincipal, no name on this device); " +
                "CONTOSO-PC\helpdesk ($script:Machine-1001, LocalAccount). " +
                "Built in or allowed: CONTOSO-PC\Administrator ($script:Machine-500, BuiltInAdministrator).")
        }

        It 'says none where a list is empty' {
            $verdict = Get-Verdict -Mode Inventory -Member @($script:BuiltIn)

            $verdict.Detail | Should -BeLike '1 member(s). Not allowed: none. Built in or allowed: *'
        }

        It 'applies the allow-list, so a list can be tried before Detect is switched on' {
            $verdict = Get-Verdict -Mode Inventory -Member @($script:BuiltIn, $script:Role) -AllowedSid $script:EntraRole

            $verdict.Detail | Should -BeLike '2 member(s). Not allowed: none. Built in or allowed: *'
        }
    }

    Context 'the members it returns' {

        It 'says what each member is and why it is expected' {
            $verdict = Get-Verdict -Member @($script:BuiltIn, $script:DomainAdmins, $script:User)

            @($verdict.Members | ForEach-Object Kind) | Should -Be @('BuiltInAdministrator', 'DomainAdmins', 'EntraPrincipal')
            @($verdict.Members | ForEach-Object IsExpected) | Should -Be @($true, $true, $false)
            @($verdict.Members | ForEach-Object Reason) | Should -Be @('built in', 'added by the domain join', '')
        }
    }
}

Describe 'Test-LocalAdministrators.ps1' -Skip:(-not $script:OnWindows) {

    BeforeAll {
        $stubs = [ordered]@{
            'Get-MachineSid'                = { $Fake.MachineSid }
            'Get-AdministratorsGroupMember' = {
                if ($Fake.GroupUnreadable) { throw 'The specified local group does not exist.' }
                foreach ($entry in @($Fake.Members)) { [pscustomobject]@{ Sid = $entry.Sid; Name = $entry.Name } }
            }
        }
        $script:Stubbed = ConvertTo-StubbedScript -Path $script:ScriptPath -Stub $stubs `
            -Destination (Join-Path -Path $TestDrive -ChildPath 'Test-LocalAdministrators.ps1')

        $script:Detect = $script:LogArguments + @('-Mode', 'Detect')
    }

    Context 'Inventory mode, as the script ships' {

        It 'exits 0 and lists the members, even those that would not be allowed' {
            $device = Get-FakeDevice -Member @($script:BuiltIn, $script:Role, $script:LocalUser)

            $run = Invoke-RemediationScript -Path $script:Stubbed -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Output | Should -HaveCount 1
            $run.Output[0] | Should -BeLike "Inventory: 3 member(s). Not allowed: $script:EntraRole (EntraPrincipal, no name on this device); CONTOSO-PC\helpdesk (*"
        }

        It 'reads the machine SID and the group once each' {
            $run = Invoke-RemediationScript -Path $script:Stubbed -ArgumentList $script:LogArguments -Fake (Get-FakeDevice)

            @(Get-FakeCall -Run $run | ForEach-Object { $_.Name }) | Should -Be @('Get-MachineSid', 'Get-AdministratorsGroupMember')
        }
    }

    Context 'Detect mode' {

        It 'exits 0 and reports Expected when every member is built in' {
            $device = Get-FakeDevice -Member @($script:BuiltIn, $script:DomainAdmins)

            $run = Invoke-RemediationScript -Path $script:Stubbed -ArgumentList $script:Detect -Fake $device

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Output | Should -HaveCount 1
            $run.Output[0] | Should -Be 'Expected: all 2 member(s) are built in or allowed.'
        }

        It 'exits 1 and names the member that is not allowed' {
            $device = Get-FakeDevice -Member @($script:BuiltIn, $script:User)

            $run = Invoke-RemediationScript -Path $script:Stubbed -ArgumentList $script:Detect -Fake $device

            $run.ExitCode | Should -Be 1 -Because $run.Error
            $run.Output | Should -HaveCount 1
            $run.Output[0] | Should -Be "Unexpected: 1 of 2 member(s) are not allowed: AzureAD\AdeleVance ($script:EntraUser, EntraPrincipal)."
        }

        It 'exits 0 with an allow-list given as one comma-separated string, as -File passes it' {
            $device = Get-FakeDevice -Member @($script:BuiltIn, $script:Role, $script:User, $script:LapsAccount)
            $arguments = $script:Detect + @('-AllowedSid', "$script:EntraRole,$script:EntraUser", '-AllowedLocalAccountName', 'LapsAdmin')

            $run = Invoke-RemediationScript -Path $script:Stubbed -ArgumentList $arguments -Fake $device

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Output[0] | Should -Be 'Expected: all 4 member(s) are built in or allowed.'
        }

        It 'keeps the output within 2048 characters, with the token first, for a crowded group' {
            $crowd = @(1..80 | ForEach-Object { Get-FakeMember -Sid "$script:Machine-$(2000 + $_)" -Name "CONTOSO-PC\account$_" })
            $device = Get-FakeDevice -Member (@($script:BuiltIn) + $crowd)

            $run = Invoke-RemediationScript -Path $script:Stubbed -ArgumentList $script:Detect -Fake $device

            $run.ExitCode | Should -Be 1 -Because $run.Error
            $run.Output | Should -HaveCount 1
            $run.Output[0].Length | Should -Be 2048
            $run.Output[0] | Should -BeLike 'Unexpected: 80 of 81 member(s) are not allowed: *...'
        }

        It 'logs every member with its verdict, so a truncated line loses nothing' {
            $folder = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('n'))
            $device = Get-FakeDevice -Member @($script:BuiltIn, $script:User)

            $null = Invoke-RemediationScript -Path $script:Stubbed -ArgumentList @('-LogDirectory', $folder, '-Mode', 'Detect') -Fake $device

            $log = @(Get-Content -LiteralPath (Join-Path -Path $folder -ChildPath 'Test-LocalAdministrators.log'))
            @($log -like "*Member CONTOSO-PC\Administrator ($script:Machine-500, BuiltInAdministrator): expected, built in.") | Should -HaveCount 1
            @($log -like "*`[WARN`]*Member AzureAD\AdeleVance ($script:EntraUser, EntraPrincipal): not allowed.") | Should -HaveCount 1
        }
    }

    Context 'a check that cannot be completed' {

        It 'exits 2, never 1, when the group cannot be read' {
            $run = Invoke-RemediationScript -Path $script:Stubbed -ArgumentList $script:Detect -Fake (Get-FakeDevice -GroupUnreadable)

            $run.ExitCode | Should -Be 2
            $run.Output | Should -BeNullOrEmpty
            $run.Error | Should -Match 'Detection failed: The specified local group does not exist\.'
        }

        It 'exits 2, never 1, when the machine SID cannot be read' {
            $run = Invoke-RemediationScript -Path $script:Stubbed -ArgumentList $script:Detect -Fake (Get-FakeDevice -MachineSid 'unknown')

            $run.ExitCode | Should -Be 2
            $run.Output | Should -BeNullOrEmpty
            $run.Error | Should -Match "Detection failed: Could not read the machine SID \(got 'unknown'\)\."
        }

        It 'exits 2, never 1, when the allow-list holds something that is not a SID' {
            $device = Get-FakeDevice -Member @($script:BuiltIn, $script:User)
            $arguments = $script:Detect + @('-AllowedSid', "$script:EntraUser,AdeleVance")

            $run = Invoke-RemediationScript -Path $script:Stubbed -ArgumentList $arguments -Fake $device

            $run.ExitCode | Should -Be 2
            $run.Output | Should -BeNullOrEmpty
            $run.Error | Should -Match "Detection failed: 'AdeleVance' in AllowedSid is not a SID\."
        }
    }
}

# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/zenpachi-alt/endpoint-engineering

#Requires -Version 5.1

<#
.SYNOPSIS
    Runs the repository's quality checks, the same way locally and in CI.

.DESCRIPTION
    CI calls this script for every check it runs, so a local run is the CI
    run. Every selected check runs even after one fails, and a summary at the
    end gives each result.

    Analyzer           PSScriptAnalyzer over every script, with
                       PSScriptAnalyzerSettings.psd1.
    Compatibility      Every script that declares #Requires -Version 5.1, with
                       PSScriptAnalyzerSettings.WindowsPowerShell.psd1.
    Scan               Tools/Test-SensitiveContent.ps1 over the working tree,
                       matched values masked.
    Readme             Every folder has a README.md, except .git, .github,
                       .claude and .vscode.
    Version            Since -Base: every script whose code changed declares a
                       higher Version under .NOTES, every new script declares
                       one, and every region whose '#region' line carries a
                       version raises it when its code changes. Comments are
                       not code; #Requires lines are. Test files and Templates/
                       are left out of the script rule, not the region rule.
                       Needs git.
    Pester             Under PowerShell 7, every *.Tests.ps1. Under Windows
                       PowerShell, the tests that declare #Requires -Version 5.1.
    Parse              Every script that declares 5.1, through the Windows
                       PowerShell 5.1 parser. Windows PowerShell only.
    WindowsPowerShell  From PowerShell 7 on Windows: Parse and Pester again,
                       in powershell.exe, so one command covers both editions.

    Without -Check, the host decides what runs:
        PowerShell 7 on Windows   every check; Parse as part of WindowsPowerShell
        PowerShell 7 elsewhere    all but Parse and WindowsPowerShell
        Windows PowerShell        Parse and Pester

    Pester runs with $ErrorActionPreference = 'Stop', the preference GitHub's
    PowerShell shells start every CI step with, so a test that fails only
    under it fails locally too. This script's strict mode is switched off for
    the tests, which would otherwise inherit it.

    The module versions CI uses are pinned here, in $PinnedModule, and each
    check imports exactly the pinned version. A missing one stops the check
    with the command that installs it; -InstallModule installs it instead.

    Unlike the other scripts in this repository, this one does not run on its
    own outside a clone: it exists to run the repository's own files, the
    scanner and the tests.

.PARAMETER Check
    The checks to run. Without it, every check the host can run.

.PARAMETER Path
    The repository to check. Defaults to the clone this script is in.

.PARAMETER Base
    The commit or branch the Version check compares with. It compares the
    working tree with the commit where HEAD left this one, so uncommitted
    changes count. Defaults to origin/main. CI passes HEAD^1: in a pull
    request, the tip of the branch it merges into; on main, the commit before.

.PARAMETER InstallModule
    Install a pinned module version that is missing, for the current user,
    from the PowerShell Gallery. CI runs with it. Windows PowerShell and
    PowerShell 7 keep separate modules, so locally it is needed once in each.

.PARAMETER Strict
    Fail, rather than warn, when the Graph helper tests would run against a
    Microsoft.Graph.Authentication other than the pinned version, or without
    one. Those tests import the highest version installed, so a newer copy
    would silently replace the pin. CI runs with it.

.PARAMETER PesterOutput
    How much Pester prints: None, Normal (failures and totals) or Detailed
    (every test). CI uses Detailed.

.EXAMPLE
    .\Tools\Invoke-RepositoryCheck.ps1

    Every check the host can run. Under PowerShell 7 on Windows, that is
    everything CI runs, both editions included.

.EXAMPLE
    .\Tools\Invoke-RepositoryCheck.ps1 -Check Analyzer, Scan

    Only the analyzer and the scan, for a quick check before committing.

.EXAMPLE
    .\Tools\Invoke-RepositoryCheck.ps1 -InstallModule

    Installs any pinned module that is missing, then runs every check.

.EXAMPLE
    .\Tools\Invoke-RepositoryCheck.ps1 -Check Version -Base main

    Which scripts changed since this branch left the local main, and whether
    each raised its Version.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.1.0
    Last updated  : 2026-11-04

    PowerShell    : 5.1 or later. CI runs Parse and Pester under Windows
                    PowerShell 5.1, and every check under PowerShell 7.
    Graph scopes  : None. Nothing reaches a tenant.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : PSScriptAnalyzer and Pester, at the versions pinned in
                    $PinnedModule. Microsoft.Graph.Authentication at its pinned
                    version lets the Graph helper tests run against the real
                    SDK; without it, that part of them is skipped. The Version
                    check needs git on the PATH.
    Role required : None.

    Exit codes    : 0 every selected check passed.
                    1 a check failed or could not run, or the selection was
                      one this host cannot run.
#>

[CmdletBinding()]
[OutputType([string])]
param (
    [Parameter()]
    [ValidateSet('Analyzer', 'Compatibility', 'Scan', 'Readme', 'Version', 'Pester', 'Parse', 'WindowsPowerShell')]
    [string[]]$Check,

    [Parameter()]
    [ValidateScript({
            if (Test-Path -LiteralPath $_ -PathType Container) { $true }
            else { throw "No folder at '$_'." }
        })]
    [string]$Path = (Split-Path -Path $PSScriptRoot -Parent),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Base = 'origin/main',

    [Parameter()]
    [switch]$InstallModule,

    [Parameter()]
    [switch]$Strict,

    [Parameter()]
    [ValidateSet('None', 'Normal', 'Detailed')]
    [string]$PesterOutput = 'Normal'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExitPassed = 0
$ExitFailed = 1

# The module versions CI installs and imports, exactly. Raise one only after every check passes
# locally against the new release. Test-EditedScript.ps1 carries a copy of the PSScriptAnalyzer
# pin, and its tests fail until the copy is raised too.
$PinnedModule = @{
    'PSScriptAnalyzer'               = [version]'1.25.0'
    'Pester'                         = [version]'6.2.0'
    'Microsoft.Graph.Authentication' = [version]'2.41.2'
}

# The order checks run in: the quick ones first.
$CheckOrder = @('Analyzer', 'Compatibility', 'Scan', 'Readme', 'Version', 'Pester', 'Parse', 'WindowsPowerShell')

$IsDesktop = $PSVersionTable.PSEdition -eq 'Desktop'
$OnWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
$Edition = if ($IsDesktop) { 'Windows PowerShell {0}' -f $PSVersionTable.PSVersion } else { 'PowerShell {0}' -f $PSVersionTable.PSVersion }
$Results = [System.Collections.Generic.List[object]]::new()

# What the checks read of the parameters, gathered at script level, where PSScriptAnalyzer
# sees them used: it does not follow a parameter into the functions that read it.
$Options = @{ InstallModule = [bool]$InstallModule; Strict = [bool]$Strict; PesterOutput = $PesterOutput; Base = $Base }

function Add-CheckResult {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [ValidateSet('Passed', 'Failed')] [string]$Result,
        [Parameter(Mandatory)] [string]$Detail
    )

    $Results.Add([pscustomobject]@{ Check = $Name; Result = $Result; Detail = $Detail })
}

function Get-RelativePath {
    [CmdletBinding()]
    [OutputType([string])]
    param ([Parameter(Mandatory)] [string]$FullName)

    $FullName.Substring($Path.Length).TrimStart('\', '/')
}

function Get-WindowsPowerShellFile {
    # The files that declare #Requires -Version 5.1, the line CI reads as the contract.
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo])]
    param ([Parameter(Mandatory)] [string]$Filter)

    Get-ChildItem -LiteralPath $Path -Filter $Filter -Recurse -File |
        Where-Object { (Get-Content -LiteralPath $_.FullName -TotalCount 20) -match '^\s*#Requires\s+-Version\s+5\.1\s*$' }
}

function Install-PinnedModule {
    [CmdletBinding()]
    param ([Parameter(Mandatory)] [string]$Name)

    if ($IsDesktop) {
        # Windows PowerShell's PowerShellGet cannot reach the Gallery until the NuGet provider is
        # present, and .NET Framework does not always offer the TLS 1.2 the Gallery requires.
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor
        [Net.SecurityProtocolType]::Tls12
        $null = Install-PackageProvider -Name NuGet -Scope CurrentUser -Force -ErrorAction Stop
    }
    $install = @{ Name = $Name; RequiredVersion = $PinnedModule[$Name]; Scope = 'CurrentUser'; Force = $true }
    # Windows ships Pester 3.4, signed by another publisher, which would block the install.
    if ($Name -eq 'Pester') { $install['SkipPublisherCheck'] = $true }
    Write-Output ('Installing {0} {1} for {2}.' -f $Name, $PinnedModule[$Name], $Edition)
    Install-Module @install -ErrorAction Stop
}

function Import-PinnedModule {
    [CmdletBinding()]
    param ([Parameter(Mandatory)] [string]$Name)

    $version = $PinnedModule[$Name]
    if (-not (Get-Module -ListAvailable -Name $Name | Where-Object { $_.Version -eq $version })) {
        if (-not $Options.InstallModule) {
            throw (('{0} {1} is not installed for {2}. Run this script once with -InstallModule, or: ' +
                    'Install-Module -Name {0} -RequiredVersion {1} -Scope CurrentUser{3}') -f $Name, $version, $Edition,
                $(if ($Name -eq 'Pester') { ' -SkipPublisherCheck' } else { '' }))
        }
        Install-PinnedModule -Name $Name
    }
    Import-Module -Name $Name -RequiredVersion $version -ErrorAction Stop
}

function Confirm-GraphModulePin {
    # The Graph helper tests import the highest Microsoft.Graph.Authentication installed,
    # whatever this script pins, so the pin is only kept by checking what that would be.
    [CmdletBinding()]
    param ()

    $name = 'Microsoft.Graph.Authentication'
    $pin = $PinnedModule[$name]
    if ($Options.InstallModule -and -not (Get-Module -ListAvailable -Name $name | Where-Object { $_.Version -eq $pin })) {
        Install-PinnedModule -Name $name
    }
    $highest = Get-Module -ListAvailable -Name $name | Sort-Object -Property Version -Descending | Select-Object -First 1

    $problem = $null
    if ($null -eq $highest) {
        $problem = 'is not installed, so the Graph helper tests skip their real-SDK part'
    }
    elseif ($highest.Version -ne $pin) {
        $problem = 'would be {0} in the tests, not the pinned {1}. Raise the pin, or remove the newer copy' -f
        $highest.Version, $pin
    }
    if ($null -ne $problem) {
        $message = '{0} {1}.' -f $name, $problem
        if ($Options.Strict) { throw $message }
        Write-Warning $message
    }
}

function Invoke-AnalyzerCheck {
    [CmdletBinding()]
    param ()

    Import-PinnedModule -Name PSScriptAnalyzer
    $settings = Join-Path -Path $Path -ChildPath 'PSScriptAnalyzerSettings.psd1'
    $findings = @(Invoke-ScriptAnalyzer -Path $Path -Recurse -Settings $settings -ErrorAction Stop)
    if ($findings.Count -gt 0) {
        $findings | Sort-Object -Property Severity, ScriptName, Line |
            Format-Table -AutoSize -Wrap -Property Severity, RuleName, ScriptName, Line, Message |
            Out-String -Width 200 | Write-Output
        Add-CheckResult -Name Analyzer -Result Failed -Detail ('{0} finding(s)' -f $findings.Count)
        return
    }
    Add-CheckResult -Name Analyzer -Result Passed -Detail 'No findings'
}

function Invoke-CompatibilityCheck {
    [CmdletBinding()]
    param ()

    Import-PinnedModule -Name PSScriptAnalyzer
    $targets = @(Get-WindowsPowerShellFile -Filter '*.ps1')
    $settings = Join-Path -Path $Path -ChildPath 'PSScriptAnalyzerSettings.WindowsPowerShell.psd1'
    $findings = @(foreach ($target in $targets) {
            Invoke-ScriptAnalyzer -Path $target.FullName -Settings $settings -ErrorAction Stop
        })
    if ($findings.Count -gt 0) {
        $findings | Format-Table -AutoSize -Wrap -Property Severity, RuleName, ScriptName, Line, Message |
            Out-String -Width 200 | Write-Output
        Add-CheckResult -Name Compatibility -Result Failed -Detail ('{0} finding(s) in scripts that declare 5.1' -f $findings.Count)
        return
    }
    Add-CheckResult -Name Compatibility -Result Passed -Detail ('{0} script(s) declare 5.1 and are compatible with it' -f $targets.Count)
}

function Invoke-ScanCheck {
    [CmdletBinding()]
    param ()

    $scanner = Join-Path -Path $Path -ChildPath 'Tools/Test-SensitiveContent.ps1'
    if (-not (Test-Path -LiteralPath $scanner -PathType Leaf)) { throw "No scanner at '$scanner'." }
    # Values stay masked: a CI log is public once the repository is.
    $findings = @(& $scanner)
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        $findings | Format-Table -AutoSize -Wrap -Property Severity, Rule, File, Line, Match, Advice |
            Out-String -Width 200 | Write-Output
        $detail = if ($code -eq 1) { '{0} finding(s), values masked' -f $findings.Count } else { 'The scan itself failed' }
        Add-CheckResult -Name Scan -Result Failed -Detail $detail
        return
    }
    Add-CheckResult -Name Scan -Result Passed -Detail 'No identifiers or secrets'
}

function Invoke-ReadmeCheck {
    [CmdletBinding()]
    param ()

    # Tool configuration folders are exempt; CLAUDE.md gives the reasons.
    $missing = @(Get-ChildItem -LiteralPath $Path -Directory -Recurse -Force |
            Where-Object { (Get-RelativePath -FullName $_.FullName) -notmatch '^(\.git|\.github|\.claude|\.vscode)([\\/]|$)' } |
            Where-Object { -not (Test-Path -LiteralPath (Join-Path -Path $_.FullName -ChildPath 'README.md')) } |
            ForEach-Object { Get-RelativePath -FullName $_.FullName })
    if ($missing.Count -gt 0) {
        $missing | ForEach-Object { Write-Output ('No README.md: {0}' -f $_) }
        Add-CheckResult -Name Readme -Result Failed -Detail ('{0} folder(s) without a README.md' -f $missing.Count)
        return
    }
    Add-CheckResult -Name Readme -Result Passed -Detail 'Every folder has a README.md'
}

function Invoke-Git {
    # Git's standard output, one string per line. Git also writes progress and warnings to
    # standard error, which Windows PowerShell turns into error records once redirected, and
    # 'Stop' would throw on the first of them. Here the exit code decides instead.
    [CmdletBinding()]
    [OutputType([string])]
    param ([Parameter(Mandatory)] [string[]]$Argument)

    $ErrorActionPreference = 'Continue'
    $all = @(& git -C $Path @Argument 2>&1)
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        $stderr = @($all | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | ForEach-Object { $_.ToString() })
        throw ('git {0} exited {1}: {2}' -f ($Argument -join ' '), $code, ($stderr -join ' '))
    }
    $all | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | ForEach-Object { [string]$_ }
}

function Get-ScriptCode {
    # A script's tokens without its comments, one per line: what the Version check compares.
    # Line endings are evened out first, so a Windows checkout matches the LF in the repository.
    # #Requires lines are comments to the tokenizer, but a contract to PowerShell, so they stay.
    [CmdletBinding()]
    [OutputType([string])]
    param ([Parameter(Mandatory)] [AllowEmptyString()] [string]$Text)

    $tokens = $null
    $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseInput(($Text -replace '\r\n', "`n"), [ref]$tokens, [ref]$parseErrors)
    @($tokens | Where-Object {
            ($_.Kind -ne 'Comment' -or $_.Text -match '^#Requires\b') -and
            $_.Kind -notin 'NewLine', 'LineContinuation', 'EndOfInput'
        } | ForEach-Object { $_.Text }) -join "`n"
}

function Get-DeclaredVersion {
    # The 'Version : x.y.z' line under .NOTES, or $null.
    [CmdletBinding()]
    [OutputType([string])]
    param ([Parameter(Mandatory)] [AllowEmptyString()] [string]$Text)

    $match = [regex]::Match($Text, '(?m)^\s*Version\s*:\s*(\S+)')
    if ($match.Success) { $match.Groups[1].Value } else { $null }
}

function Get-VersionedRegion {
    # Every region whose '#region' line carries a version, as in
    # '#region TimeGuard 1.0.0 - canonical copy in ...': name -> version and code.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param ([Parameter(Mandatory)] [AllowEmptyString()] [string]$Text)

    $regions = @{}
    $lines = @($Text -split '\r?\n')
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $header = [regex]::Match($lines[$i], '^\s*#region (?<name>.+?) (?<version>\d+(\.\d+){1,3}) - ')
        if (-not $header.Success) { continue }
        $name = $header.Groups['name'].Value
        $end = '^\s*#endregion {0}\s*$' -f [regex]::Escape($name)
        for ($j = $i + 1; $j -lt $lines.Count; $j++) {
            if ($lines[$j] -cmatch $end) {
                $regions[$name] = @{
                    Version = $header.Groups['version'].Value
                    Code    = Get-ScriptCode -Text ($lines[$i..$j] -join "`n")
                }
                break
            }
        }
    }
    $regions
}

function Test-VersionRaised {
    [CmdletBinding()]
    [OutputType([bool])]
    param ([AllowNull()] [string]$Old, [AllowNull()] [string]$New)

    $oldVersion = $null
    $newVersion = $null
    if ([version]::TryParse($Old, [ref]$oldVersion) -and [version]::TryParse($New, [ref]$newVersion)) {
        return $newVersion -gt $oldVersion
    }
    $New -ne $Old
}

function Invoke-VersionCheck {
    [CmdletBinding()]
    param ()

    try { $null = Get-Command -Name git -CommandType Application -ErrorAction Stop }
    catch { throw 'The Version check needs git on the PATH.' }

    $root = @(Invoke-Git -Argument 'rev-parse', '--show-toplevel')[0]
    try { $baseCommit = @(Invoke-Git -Argument 'merge-base', 'HEAD', $Options.Base)[0] }
    catch {
        throw ("Cannot find where HEAD left '{0}'. Fetch it (git fetch origin), or name another commit with -Base. {1}" -f
            $Options.Base, $_.Exception.Message)
    }
    $since = '{0} ({1})' -f $Options.Base, $baseCommit.Substring(0, 7)

    # The working tree against the base, so uncommitted changes count, and new files not yet
    # added. A line is 'M<tab>path', 'A<tab>path' or 'R100<tab>old<tab>new'.
    $changed = [System.Collections.Generic.List[object]]::new()
    foreach ($line in @(Invoke-Git -Argument 'diff', '--name-status', '--find-renames', $baseCommit, '--')) {
        $fields = $line -split "`t"
        if ($fields[-1] -notlike '*.ps1') { continue }
        $status = $fields[0].Substring(0, 1)
        if ($status -in 'M', 'R') { $changed.Add([pscustomobject]@{ Old = $fields[1]; New = $fields[-1] }) }
        if ($status -eq 'A') { $changed.Add([pscustomobject]@{ Old = $null; New = $fields[-1] }) }
    }
    foreach ($file in @(Invoke-Git -Argument 'ls-files', '--others', '--exclude-standard', '--full-name', '--', '*.ps1')) {
        $changed.Add([pscustomobject]@{ Old = $null; New = $file })
    }

    $failures = [System.Collections.Generic.List[string]]::new()
    $raised = 0
    foreach ($entry in $changed) {
        $new = [System.IO.File]::ReadAllText((Join-Path -Path $root -ChildPath $entry.New))
        $old = if ($entry.Old) { @(Invoke-Git -Argument 'show', ('{0}:{1}' -f $baseCommit, $entry.Old)) -join "`n" } else { $null }

        # The script's own Version. Test files are not copied out and carry none. In
        # Templates/ a Version is where new work starts, and the shared blocks there are
        # held by the region rule below instead.
        if ($entry.New -notlike '*.Tests.ps1' -and $entry.New -notlike 'Templates/*') {
            $newVersion = Get-DeclaredVersion -Text $new
            if ($null -eq $old) {
                if ($null -eq $newVersion) { $failures.Add(('{0}: new, and declares no Version under .NOTES' -f $entry.New)) }
            }
            elseif ((Get-ScriptCode -Text $old) -cne (Get-ScriptCode -Text $new)) {
                $oldVersion = Get-DeclaredVersion -Text $old
                if (Test-VersionRaised -Old $oldVersion -New $newVersion) { $raised++ }
                else {
                    $failures.Add(('{0}: the code changed, but Version is {1}, and was {2}' -f $entry.New,
                            $(if ($newVersion) { $newVersion } else { 'missing' }), $(if ($oldVersion) { $oldVersion } else { 'missing' })))
                }
            }
        }

        # Every versioned region, in any script: a copy says which revision of the block it holds.
        if ($null -eq $old) { continue }
        $oldRegions = Get-VersionedRegion -Text $old
        $newRegions = Get-VersionedRegion -Text $new
        foreach ($name in @($newRegions.Keys | Sort-Object)) {
            if (-not $oldRegions.ContainsKey($name)) { continue }
            if ($oldRegions[$name].Code -ceq $newRegions[$name].Code) { continue }
            if (-not (Test-VersionRaised -Old $oldRegions[$name].Version -New $newRegions[$name].Version)) {
                $failures.Add(('{0}: the code of the {1} region changed, but its version is {2}, and was {3}' -f $entry.New, $name,
                        $newRegions[$name].Version, $oldRegions[$name].Version))
            }
        }
    }

    if ($failures.Count -gt 0) {
        $failures | ForEach-Object { Write-Output $_ }
        Write-Output (('Compared with {0}. Raise the version: the last number for a fix, the middle one for new ' +
                'behaviour. A change to a shared region raises the region''s version and the Version of every ' +
                'script that carries it.') -f $since)
        Add-CheckResult -Name Version -Result Failed -Detail ('{0} version(s) to raise or declare' -f $failures.Count)
        return
    }
    $detail = if ($raised -eq 0) { 'No script''s code changed since {0}' -f $since }
    else { '{0} script(s) changed since {1}, each with a higher Version' -f $raised, $since }
    Add-CheckResult -Name Version -Result Passed -Detail $detail
}

function Invoke-PesterCheck {
    [CmdletBinding()]
    param ()

    Import-PinnedModule -Name Pester
    if ($IsDesktop) {
        $tests = @(Get-WindowsPowerShellFile -Filter '*.Tests.ps1' | ForEach-Object { $_.FullName })
        if ($tests.Count -eq 0) {
            Add-CheckResult -Name Pester -Result Passed -Detail 'No test declares #Requires -Version 5.1'
            return
        }
    }
    else {
        Confirm-GraphModulePin
        $tests = @($Path)
    }

    $configuration = New-PesterConfiguration
    $configuration.Run.Path = [string[]]$tests
    $configuration.Run.PassThru = $true
    $configuration.Output.Verbosity = $Options.PesterOutput
    # The tests inherit the caller's preference and strict mode. They get CI's preference,
    # and none of this script's strictness, which they were not written for.
    $run = & {
        Set-StrictMode -Off
        $ErrorActionPreference = 'Stop'
        Invoke-Pester -Configuration $configuration
    } | Select-Object -Last 1

    $detail = '{0} passed, {1} failed, {2} skipped under {3}' -f $run.PassedCount, $run.FailedCount, $run.SkippedCount, $Edition
    if ($run.Result -ne 'Passed') {
        if ($run.FailedBlocksCount -gt 0 -or $run.FailedContainersCount -gt 0) {
            $detail += '; {0} block(s) and {1} file(s) failed to run' -f $run.FailedBlocksCount, $run.FailedContainersCount
        }
        Add-CheckResult -Name Pester -Result Failed -Detail $detail
        return
    }
    Add-CheckResult -Name Pester -Result Passed -Detail $detail
}

function Invoke-ParseCheck {
    [CmdletBinding()]
    param ()

    $targets = @(Get-WindowsPowerShellFile -Filter '*.ps1')
    $failures = [System.Collections.Generic.List[string]]::new()
    foreach ($target in $targets) {
        $parseErrors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($target.FullName, [ref]$null, [ref]$parseErrors)
        foreach ($parseError in $parseErrors) {
            $failures.Add(('{0}({1}): {2}' -f (Get-RelativePath -FullName $target.FullName),
                    $parseError.Extent.StartLineNumber, $parseError.Message))
        }
    }
    if ($failures.Count -gt 0) {
        $failures | Write-Output
        Add-CheckResult -Name Parse -Result Failed -Detail ('{0} parse error(s) under {1}' -f $failures.Count, $Edition)
        return
    }
    Add-CheckResult -Name Parse -Result Passed -Detail ('{0} script(s) declare 5.1 and parse under it' -f $targets.Count)
}

function Invoke-WindowsPowerShellCheck {
    [CmdletBinding()]
    param ()

    # Started as a plain command, powershell.exe gets its own module path. Started through
    # Start-Process it would inherit PowerShell 7's, and fail to load its own core modules.
    $switches = @(
        if ($Options.InstallModule) { '-InstallModule' }
        if ($Options.Strict) { '-Strict' }
    ) -join ' '
    $command = "& '{0}' -Check Parse, Pester -Path '{1}' -PesterOutput {2} {3}; exit `$LASTEXITCODE" -f
    ($PSCommandPath -replace "'", "''"), ($Path -replace "'", "''"), $Options.PesterOutput, $switches
    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command $command
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        Add-CheckResult -Name WindowsPowerShell -Result Failed -Detail ('Parse and Pester under powershell.exe exited {0}; see above' -f $code)
        return
    }
    Add-CheckResult -Name WindowsPowerShell -Result Passed -Detail 'Parse and Pester passed under powershell.exe'
}

try {
    $Path = (Resolve-Path -LiteralPath $Path).Path.TrimEnd('\', '/')

    $selected = if ($Check) { $Check }
    elseif ($IsDesktop) { @('Parse', 'Pester') }
    elseif ($OnWindows) { @($CheckOrder | Where-Object { $_ -ne 'Parse' }) }
    else { @($CheckOrder | Where-Object { $_ -notin 'Parse', 'WindowsPowerShell' }) }

    # Refused before anything runs, so a wrong selection costs nothing.
    $unavailable = @(foreach ($name in $selected) {
            if ($IsDesktop -and $name -in 'Analyzer', 'Compatibility') {
                '{0} runs under PowerShell 7, whose parser reads every script in the repository' -f $name
            }
            if ($IsDesktop -and $name -eq 'WindowsPowerShell') {
                'WindowsPowerShell starts powershell.exe from PowerShell 7; here, use -Check Parse, Pester'
            }
            if (-not $IsDesktop -and $name -eq 'Parse') {
                'Parse needs the Windows PowerShell parser: run it under powershell.exe, or use -Check WindowsPowerShell'
            }
            if (-not $IsDesktop -and -not $OnWindows -and $name -eq 'WindowsPowerShell') {
                'WindowsPowerShell needs Windows'
            }
        })
    if ($unavailable.Count -gt 0) { throw ($unavailable -join '. ') }
}
catch {
    Write-Error -Exception $_.Exception -Message ('Cannot run the checks: {0}' -f $_.Exception.Message) -ErrorAction Continue
    exit $ExitFailed
}

Write-Output ('Checking {0} under {1}' -f $Path, $Edition)
foreach ($name in @($CheckOrder | Where-Object { $_ -in $selected })) {
    Write-Output ''
    Write-Output ('== {0}' -f $name)
    try {
        switch ($name) {
            'Analyzer' { Invoke-AnalyzerCheck }
            'Compatibility' { Invoke-CompatibilityCheck }
            'Scan' { Invoke-ScanCheck }
            'Readme' { Invoke-ReadmeCheck }
            'Version' { Invoke-VersionCheck }
            'Pester' { Invoke-PesterCheck }
            'Parse' { Invoke-ParseCheck }
            'WindowsPowerShell' { Invoke-WindowsPowerShellCheck }
        }
    }
    catch {
        # One check that cannot run must not hide the result of the others.
        Write-Error -Exception $_.Exception -Message ('{0} could not run: {1}' -f $name, $_.Exception.Message) -ErrorAction Continue
        Add-CheckResult -Name $name -Result Failed -Detail ('Could not run: {0}' -f $_.Exception.Message)
    }
}

Write-Output ''
$Results | Format-Table -AutoSize -Wrap -Property Check, Result, Detail | Out-String -Width 200 | Write-Output
if (@($Results | Where-Object { $_.Result -eq 'Failed' }).Count -gt 0) { exit $ExitFailed }
exit $ExitPassed

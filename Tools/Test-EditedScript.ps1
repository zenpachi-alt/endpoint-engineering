# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/zenpachi-alt/endpoint-engineering

#Requires -Version 5.1

<#
.SYNOPSIS
    Runs PSScriptAnalyzer over one PowerShell file the way CI does, for the
    Claude Code hook that fires after every edit.

.DESCRIPTION
    CI fails on any PSScriptAnalyzer finding, and on any Windows PowerShell 5.1
    incompatibility in a script that declares 5.1. This script applies the same
    two checks to a single file, so a finding reaches Claude in the turn that
    caused it rather than in a failed CI run after the push.

    With -Path it checks that file. Without it, it reads the JSON that a Claude
    Code PostToolUse hook receives on standard input and checks the file the
    edit touched. Anything that is not a .ps1, .psm1 or .psd1 file inside this
    repository is ignored.

    The file is analysed with PSScriptAnalyzerSettings.psd1 from the repository
    root, as the Analyzer check does. A .ps1 file that declares
    '#Requires -Version 5.1' is also analysed with
    PSScriptAnalyzerSettings.WindowsPowerShell.psd1, as the Compatibility check
    does.

    Findings go to standard error, one line each, and the script exits 2: the
    code on which Claude Code passes a PostToolUse hook's standard error to
    Claude.

.PARAMETER Path
    The file to check. Omit it to read a Claude Code hook's JSON from standard
    input instead.

.EXAMPLE
    .\Tools\Test-EditedScript.ps1 -Path .\Tools\Install-GitHook.ps1

    Checks one script by hand. Prints nothing and exits 0 when it is clean.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.0.0
    Last updated  : 2026-10-21

    PowerShell    : 5.1 or 7. The hook starts it under PowerShell 7, where CI
                    runs the analyzer.
    Graph scopes  : None.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : PSScriptAnalyzer 1.25.0, the version
                    Invoke-RepositoryCheck.ps1 pins; the tests fail while the
                    two differ. Install it with
                    .\Tools\Invoke-RepositoryCheck.ps1 -InstallModule.
    Role required : None.

    Exit codes    : 0 clean, or not a PowerShell file in this repository;
                    1 the check itself failed; 2 findings.

    It reads the analyzer settings from the repository root, so it runs only
    inside a clone.
#>

[CmdletBinding()]
param (
    [Parameter(Position = 0)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExitClean = 0
$ExitError = 1
$ExitFindings = 2

# Copies of what Invoke-RepositoryCheck.ps1 uses, which this script cannot load from it. The tests
# fail while either copy differs from the original.
$AnalyzerVersion = [version]'1.25.0'
$WindowsPowerShellDeclaration = '^\s*#Requires\s+-Version\s+5\.1\s*$'

$PowerShellExtension = @('.ps1', '.psm1', '.psd1')

function Read-HookInput {
    # The JSON Claude Code writes to a hook's standard input, read as UTF-8 whatever the console uses.
    [CmdletBinding()]
    [OutputType([string])]
    param ()

    $encoding = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
    $reader = New-Object -TypeName System.IO.StreamReader -ArgumentList ([Console]::OpenStandardInput()), $encoding
    try {
        $reader.ReadToEnd()
    }
    finally {
        $reader.Dispose()
    }
}

function Get-EditedFilePath {
    # The full path of the file a hook's input names, or nothing when it names none.
    [CmdletBinding()]
    [OutputType([string])]
    param ([Parameter(Mandatory)] [AllowEmptyString()] [string]$HookInput)

    if ([string]::IsNullOrWhiteSpace($HookInput)) { return }
    $hookEvent = $HookInput | ConvertFrom-Json -ErrorAction Stop

    $toolInput = $hookEvent.PSObject.Properties['tool_input']
    if ($null -eq $toolInput -or $null -eq $toolInput.Value) { return }
    $filePath = $toolInput.Value.PSObject.Properties['file_path']
    if ($null -eq $filePath -or [string]::IsNullOrWhiteSpace([string]$filePath.Value)) { return }

    # Edit and Write pass absolute paths; a relative one is taken from the session's directory.
    $directory = $hookEvent.PSObject.Properties['cwd']
    $base = if ($null -ne $directory -and $directory.Value) { [string]$directory.Value }
    else { (Get-Location -PSProvider FileSystem).ProviderPath }
    [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($base, [string]$filePath.Value))
}

function Test-InsideRepository {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [string]$RepositoryRoot
    )

    $comparison = if ([System.IO.Path]::DirectorySeparatorChar -eq '\') { [System.StringComparison]::OrdinalIgnoreCase }
    else { [System.StringComparison]::Ordinal }
    $FilePath.StartsWith($RepositoryRoot + [System.IO.Path]::DirectorySeparatorChar, $comparison)
}

try {
    $repositoryRoot = [System.IO.Path]::GetFullPath((Split-Path -Path $PSScriptRoot -Parent)).TrimEnd('\', '/')

    if ($PSBoundParameters.ContainsKey('Path')) {
        $target = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
    }
    elseif ([Console]::IsInputRedirected) {
        $target = Get-EditedFilePath -HookInput (Read-HookInput)
    }
    else {
        throw 'Pass -Path, or pipe in the JSON a Claude Code hook receives.'
    }

    if (-not $target) {
        Write-Verbose 'The input names no file.'
        exit $ExitClean
    }
    $extension = [System.IO.Path]::GetExtension($target)
    if ($extension -notin $PowerShellExtension) {
        Write-Verbose "Not a PowerShell file: $target"
        exit $ExitClean
    }
    if (-not (Test-InsideRepository -FilePath $target -RepositoryRoot $repositoryRoot)) {
        Write-Verbose "Outside this repository: $target"
        exit $ExitClean
    }
    if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
        Write-Verbose "No longer exists: $target"
        exit $ExitClean
    }

    try {
        Import-Module -Name PSScriptAnalyzer -RequiredVersion $AnalyzerVersion -ErrorAction Stop
    }
    catch {
        throw ('PSScriptAnalyzer {0} is not installed for PowerShell {1}. Install it with .\Tools\Invoke-RepositoryCheck.ps1 -InstallModule.' -f
            $AnalyzerVersion, $PSVersionTable.PSVersion)
    }

    $settings = Join-Path -Path $repositoryRoot -ChildPath 'PSScriptAnalyzerSettings.psd1'
    $findings = @(Invoke-ScriptAnalyzer -Path $target -Settings $settings -ErrorAction Stop)

    # The first 20 lines, as Invoke-RepositoryCheck.ps1 reads them to pick the files CI holds to 5.1.
    $declaresWindowsPowerShell = $extension -eq '.ps1' -and
        @(Get-Content -LiteralPath $target -TotalCount 20 -ErrorAction Stop) -match $WindowsPowerShellDeclaration
    if ($declaresWindowsPowerShell) {
        $compatibility = Join-Path -Path $repositoryRoot -ChildPath 'PSScriptAnalyzerSettings.WindowsPowerShell.psd1'
        $findings += @(Invoke-ScriptAnalyzer -Path $target -Settings $compatibility -ErrorAction Stop)
    }

    if ($findings.Count -eq 0) {
        Write-Verbose "No findings: $target"
        exit $ExitClean
    }

    $relativePath = $target.Substring($repositoryRoot.Length + 1)
    $report = @('PSScriptAnalyzer: {0} finding(s) in {1}. CI fails on each of them.' -f $findings.Count, $relativePath)
    $report += @($findings | Sort-Object -Property Line, RuleName | ForEach-Object {
            '  Line {0}: {1} {2}: {3}' -f $_.Line, $_.Severity, $_.RuleName, $_.Message
        })

    # Claude Code hands a PostToolUse hook's standard error to Claude when it exits 2. The report is
    # written there as plain lines; Write-Error would wrap it in an error record's formatting.
    [Console]::Error.WriteLine(($report -join [Environment]::NewLine))
    exit $ExitFindings
}
catch {
    Write-Error -Message "Could not check the edited file: $($_.Exception.Message)" -ErrorAction Continue
    exit $ExitError
}

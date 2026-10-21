# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/zenpachi-alt/endpoint-engineering

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

<#
.SYNOPSIS
    Pester tests for Test-EditedScript.ps1.

.DESCRIPTION
    Each test copies the script and the two analyzer settings files into a small
    repository in Pester's TestDrive and starts the copy in a child process, as
    the Claude Code hook does, so standard input, standard error and the exit
    code are all real. The real repository is never the subject.

    The tests that run PSScriptAnalyzer need its pinned version, and run only
    under PowerShell 7, where CI runs the analyzer. They skip elsewhere; in CI
    they run in the Linux job, whose Analyzer step installs the pin first.

.EXAMPLE
    Invoke-Pester -Path .\Tools\Test-EditedScript.Tests.ps1 -Output Detailed

.NOTES
    PowerShell    : 5.1 or later, matching the script under test.
    Graph scopes  : None.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : Pester 5.5.0 or later. PSScriptAnalyzer at the pinned
                    version for the tests that analyse.
#>

BeforeDiscovery {
    $scriptText = Get-Content -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath 'Test-EditedScript.ps1') -Raw
    $pin = [version][regex]::Match($scriptText, '\$AnalyzerVersion = \[version\]\x27([^\x27]+)\x27').Groups[1].Value
    $script:SkipAnalysis = $PSVersionTable.PSEdition -eq 'Desktop' -or
        -not (Get-Module -ListAvailable -Name PSScriptAnalyzer | Where-Object { $_.Version -eq $pin })
}

BeforeAll {
    $script:ScriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'Test-EditedScript.ps1'
    $script:CheckPath = Join-Path -Path $PSScriptRoot -ChildPath 'Invoke-RepositoryCheck.ps1'
    $script:RepositoryRoot = Split-Path -Path $PSScriptRoot -Parent
    $script:PowerShellPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

    function Write-TestRepository {
        # A repository root holding a copy of the script, the two settings files and the given files.
        param ([hashtable]$File = @{})
        $root = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('n'))
        $tools = Join-Path -Path $root -ChildPath 'Tools'
        $null = New-Item -ItemType Directory -Path $tools
        Copy-Item -LiteralPath $script:ScriptPath -Destination $tools
        foreach ($name in 'PSScriptAnalyzerSettings.psd1', 'PSScriptAnalyzerSettings.WindowsPowerShell.psd1') {
            Copy-Item -LiteralPath (Join-Path -Path $script:RepositoryRoot -ChildPath $name) -Destination $root
        }
        foreach ($relative in $File.Keys) {
            $target = Join-Path -Path $root -ChildPath $relative
            $null = New-Item -ItemType Directory -Path (Split-Path -Path $target -Parent) -Force
            [IO.File]::WriteAllText($target, $File[$relative])
        }
        $root
    }

    function ConvertTo-HookInput {
        # The JSON a PostToolUse hook receives after an Edit.
        param ([string]$FilePath, [string]$WorkingDirectory)
        @{
            hook_event_name = 'PostToolUse'
            tool_name       = 'Edit'
            cwd             = $WorkingDirectory
            tool_input      = @{ file_path = $FilePath }
        } | ConvertTo-Json -Compress
    }

    function Invoke-UnderTest {
        # Starts the repository's copy in a child process and returns its exit code and output.
        param ([string]$Repository, [string[]]$Argument = @(), [string]$InputText = '')
        $arguments = @('-NoProfile', '-NonInteractive')
        if ($PSVersionTable.PSEdition -eq 'Desktop') { $arguments += '-ExecutionPolicy', 'Bypass' }
        $arguments += '-File', (Join-Path -Path $Repository -ChildPath 'Tools/Test-EditedScript.ps1')
        $arguments += $Argument

        $info = New-Object -TypeName System.Diagnostics.ProcessStartInfo
        $info.FileName = $script:PowerShellPath
        $info.Arguments = @($arguments | ForEach-Object { '"{0}"' -f $_ }) -join ' '
        $info.UseShellExecute = $false
        $info.RedirectStandardInput = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true

        $process = [System.Diagnostics.Process]::Start($info)
        try {
            $process.StandardInput.Write($InputText)
            $process.StandardInput.Close()
            $errorText = $process.StandardError.ReadToEndAsync()
            $outputText = $process.StandardOutput.ReadToEnd()
            $process.WaitForExit()
            [pscustomobject]@{
                ExitCode = $process.ExitCode
                Output   = $outputText
                Error    = $errorText.Result
            }
        }
        finally {
            $process.Dispose()
        }
    }
}

Describe 'Test-EditedScript' {

    Context 'Choosing the file' {

        It 'ignores a file that is not PowerShell' {
            $repository = Write-TestRepository -File @{ 'README.md' = '# Test' }
            $hookInput = ConvertTo-HookInput -FilePath (Join-Path -Path $repository -ChildPath 'README.md') -WorkingDirectory $repository

            $result = Invoke-UnderTest -Repository $repository -InputText $hookInput

            $result.ExitCode | Should -Be 0
            $result.Error | Should -BeNullOrEmpty
        }

        It 'ignores a PowerShell file outside the repository' {
            $repository = Write-TestRepository
            $outside = Join-Path -Path $TestDrive -ChildPath 'Outside.ps1'
            [IO.File]::WriteAllText($outside, "Write-Host 'outside'")
            $hookInput = ConvertTo-HookInput -FilePath $outside -WorkingDirectory $repository

            $result = Invoke-UnderTest -Repository $repository -InputText $hookInput

            $result.ExitCode | Should -Be 0
            $result.Error | Should -BeNullOrEmpty
        }

        It 'ignores a file that no longer exists' {
            $repository = Write-TestRepository
            $hookInput = ConvertTo-HookInput -FilePath (Join-Path -Path $repository -ChildPath 'Gone.ps1') -WorkingDirectory $repository

            $result = Invoke-UnderTest -Repository $repository -InputText $hookInput

            $result.ExitCode | Should -Be 0
            $result.Error | Should -BeNullOrEmpty
        }

        It 'ignores input that names no file' {
            $repository = Write-TestRepository

            $result = Invoke-UnderTest -Repository $repository -InputText '{"tool_name":"Bash","tool_input":{"command":"ls"}}'

            $result.ExitCode | Should -Be 0
            $result.Error | Should -BeNullOrEmpty
        }

        It 'fails with exit code 1 on input that is not JSON' {
            $repository = Write-TestRepository

            $result = Invoke-UnderTest -Repository $repository -InputText 'not json'

            $result.ExitCode | Should -Be 1
            # Windows PowerShell wraps an error record at the console width.
            ($result.Error -replace '\s+', ' ') | Should -Match 'Could not check the edited file'
        }
    }

    Context 'Analysing it' {

        It 'passes a clean script without a word' -Skip:$script:SkipAnalysis {
            $content = @('[CmdletBinding()]', 'param ()', "Write-Output 'clean'") -join "`n"
            $repository = Write-TestRepository -File @{ 'Clean.ps1' = $content }
            $hookInput = ConvertTo-HookInput -FilePath (Join-Path -Path $repository -ChildPath 'Clean.ps1') -WorkingDirectory $repository

            $result = Invoke-UnderTest -Repository $repository -InputText $hookInput

            $result.ExitCode | Should -Be 0
            $result.Error | Should -BeNullOrEmpty
        }

        It 'reports a finding with exit code 2, naming the rule and the line' -Skip:$script:SkipAnalysis {
            $content = @('[CmdletBinding()]', 'param ()', "Write-Host 'noisy'") -join "`n"
            $repository = Write-TestRepository -File @{ 'Graph/Noisy.ps1' = $content }
            $hookInput = ConvertTo-HookInput -FilePath (Join-Path -Path $repository -ChildPath 'Graph/Noisy.ps1') -WorkingDirectory $repository

            $result = Invoke-UnderTest -Repository $repository -InputText $hookInput

            $result.ExitCode | Should -Be 2
            $result.Error | Should -Match '1 finding\(s\) in Graph[\\/]Noisy\.ps1'
            $result.Error | Should -Match 'Line 3: Warning PSAvoidUsingWriteHost'
        }

        It 'holds a script that declares 5.1 to Windows PowerShell syntax' -Skip:$script:SkipAnalysis {
            $content = @('#Requires -Version 5.1', '[CmdletBinding()]', 'param ()', '$value = $null', 'Write-Output ($value ?? ''fallback'')') -join "`n"
            $repository = Write-TestRepository -File @{ 'Intune/Old.ps1' = $content }
            $hookInput = ConvertTo-HookInput -FilePath (Join-Path -Path $repository -ChildPath 'Intune/Old.ps1') -WorkingDirectory $repository

            $result = Invoke-UnderTest -Repository $repository -InputText $hookInput

            $result.ExitCode | Should -Be 2
            $result.Error | Should -Match 'PSUseCompatibleSyntax'
        }

        It 'leaves the same syntax alone in a script that declares 7.0' -Skip:$script:SkipAnalysis {
            $content = @('#Requires -Version 7.0', '[CmdletBinding()]', 'param ()', '$value = $null', 'Write-Output ($value ?? ''fallback'')') -join "`n"
            $repository = Write-TestRepository -File @{ 'Graph/New.ps1' = $content }
            $hookInput = ConvertTo-HookInput -FilePath (Join-Path -Path $repository -ChildPath 'Graph/New.ps1') -WorkingDirectory $repository

            $result = Invoke-UnderTest -Repository $repository -InputText $hookInput

            $result.ExitCode | Should -Be 0
            $result.Error | Should -BeNullOrEmpty
        }

        It 'checks the file that -Path names' -Skip:$script:SkipAnalysis {
            $content = @('[CmdletBinding()]', 'param ()', "Write-Host 'noisy'") -join "`n"
            $repository = Write-TestRepository -File @{ 'Noisy.ps1' = $content }

            $result = Invoke-UnderTest -Repository $repository -Argument '-Path', (Join-Path -Path $repository -ChildPath 'Noisy.ps1')

            $result.ExitCode | Should -Be 2
            $result.Error | Should -Match 'PSAvoidUsingWriteHost'
        }
    }

    Context 'Kept in step with Invoke-RepositoryCheck.ps1' {

        It 'pins the same PSScriptAnalyzer version' {
            $own = [regex]::Match((Get-Content -LiteralPath $script:ScriptPath -Raw), '\$AnalyzerVersion = \[version\]\x27([^\x27]+)\x27').Groups[1].Value
            $pinned = [regex]::Match((Get-Content -LiteralPath $script:CheckPath -Raw), '\x27PSScriptAnalyzer\x27\s*=\s*\[version\]\x27([^\x27]+)\x27').Groups[1].Value

            $own | Should -Not -BeNullOrEmpty
            $own | Should -Be $pinned -Because 'Test-EditedScript.ps1 carries a copy of the pin in Invoke-RepositoryCheck.ps1; raise both'
        }

        It 'reads the 5.1 declaration with the same pattern' {
            $own = [regex]::Match((Get-Content -LiteralPath $script:ScriptPath -Raw), '\$WindowsPowerShellDeclaration = \x27([^\x27]+)\x27').Groups[1].Value

            $own | Should -Not -BeNullOrEmpty
            (Get-Content -LiteralPath $script:CheckPath -Raw).Contains("'$own'") |
                Should -BeTrue -Because 'Test-EditedScript.ps1 copies the pattern Invoke-RepositoryCheck.ps1 uses to pick the files that declare 5.1'
        }
    }
}

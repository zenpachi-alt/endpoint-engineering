# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/zenpachi-alt/endpoint-engineering

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

<#
.SYNOPSIS
    Pester tests for Invoke-RepositoryCheck.ps1.

.DESCRIPTION
    Each test builds a small repository in Pester's TestDrive and points the
    script at it with -Path, so the real repository is never the subject. The
    checks that need no module are tested here: Readme, Version, Parse, Scan,
    and how the script reports, selects and exits. The Version tests make
    their repository a git repository, with its own committer, so they need
    git and nothing from the git configuration of the machine. Analyzer, Compatibility and Pester
    only hand the repository to PSScriptAnalyzer and Pester; CI runs them on
    every push, and a mistake in them shows there at once.

.EXAMPLE
    Invoke-Pester -Path .\Tools\Invoke-RepositoryCheck.Tests.ps1 -Output Detailed

.NOTES
    PowerShell    : 5.1 or later, matching the script under test. The Parse
                    tests run only under Windows PowerShell, which the check
                    needs.
    Graph scopes  : None.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : Pester 5.5.0 or later. git, for the Version tests.
#>

BeforeAll {
    $script:ScriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'Invoke-RepositoryCheck.ps1'
    $script:ScannerPath = Join-Path -Path $PSScriptRoot -ChildPath 'Test-SensitiveContent.ps1'

    function Write-TestRepository {
        # A repository root with a README, and the given folders, each with a README unless listed in -Bare.
        param ([string[]]$Folder = @(), [string[]]$Bare = @(), [hashtable]$File = @{})
        $root = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('n'))
        $null = New-Item -ItemType Directory -Path $root
        Set-Content -LiteralPath (Join-Path -Path $root -ChildPath 'README.md') -Value '# Test'
        foreach ($name in $Folder + $Bare) {
            $null = New-Item -ItemType Directory -Path (Join-Path -Path $root -ChildPath $name) -Force
            if ($name -notin $Bare) {
                Set-Content -LiteralPath (Join-Path -Path $root -ChildPath "$name/README.md") -Value '# Test'
            }
        }
        foreach ($relative in $File.Keys) {
            $target = Join-Path -Path $root -ChildPath $relative
            $null = New-Item -ItemType Directory -Path (Split-Path -Path $target -Parent) -Force
            [IO.File]::WriteAllText($target, $File[$relative])
        }
        $root
    }

    function Invoke-UnderTest {
        param ([hashtable]$Parameters)
        # Warnings are captured too, so the scanner's own warning stays out of the test log.
        $all = & $script:ScriptPath @Parameters 3>&1 2>&1
        $exitCode = $LASTEXITCODE
        [pscustomobject]@{
            Text     = (@($all | Where-Object {
                        $_ -isnot [System.Management.Automation.ErrorRecord] -and
                        $_ -isnot [System.Management.Automation.WarningRecord]
                    }) -join "`n")
            Warnings = (@($all | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object Message) -join "`n")
            Errors   = (@($all | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | ForEach-Object { "$_" }) -join "`n")
            ExitCode = $exitCode
        }
    }
}

Describe 'Invoke-RepositoryCheck' {

    Context 'Readme' {

        It 'passes when every folder has a README.md' {
            $repository = Write-TestRepository -Folder 'Graph', 'Graph/Devices'

            $result = Invoke-UnderTest @{ Path = $repository; Check = 'Readme' }

            $result.ExitCode | Should -Be 0
            $result.Text | Should -Match 'Readme\s+Passed'
        }

        It 'fails and names each folder without one' {
            $repository = Write-TestRepository -Folder 'Graph' -Bare 'Graph/Groups', 'Standalone'

            $result = Invoke-UnderTest @{ Path = $repository; Check = 'Readme' }

            $result.ExitCode | Should -Be 1
            $result.Text | Should -Match 'No README\.md: Graph[\\/]Groups'
            $result.Text | Should -Match 'No README\.md: Standalone'
            $result.Text | Should -Match '2 folder\(s\) without a README\.md'
        }

        It 'exempts .git, .github, .claude and .vscode, and everything under them' {
            $repository = Write-TestRepository -Bare '.git', '.git/hooks', '.github', '.github/workflows', '.claude', '.vscode'

            (Invoke-UnderTest @{ Path = $repository; Check = 'Readme' }).ExitCode | Should -Be 0
        }

        It 'exempts those names only at the root' {
            $repository = Write-TestRepository -Folder 'Graph' -Bare 'Graph/.github'

            (Invoke-UnderTest @{ Path = $repository; Check = 'Readme' }).ExitCode | Should -Be 1
        }
    }

    Context 'Version' {

        BeforeAll {
            function Invoke-TestGit {
                # Git in a test repository, with a committer of its own. Windows PowerShell turns
                # git's standard error into error records, which 'Stop' would throw on.
                param ([string]$Repository, [string[]]$Argument)
                $ErrorActionPreference = 'Continue'
                $output = & git -C $Repository -c user.name=Test -c user.email=test@example.com -c core.autocrlf=false @Argument 2>&1
                if ($LASTEXITCODE -ne 0) { throw ('git {0} failed: {1}' -f ($Argument -join ' '), ($output -join ' ')) }
            }

            function Get-ScriptText {
                # A script with help, a Version under .NOTES and a body, in LF.
                param ([string]$Version = '1.0.0', [string]$Body = "Write-Output 'one'", [string]$Requires = '5.1',
                    [string]$Synopsis = 'Does one thing.')
                @(
                    "#Requires -Version $Requires"
                    '<#'
                    '.SYNOPSIS'
                    "    $Synopsis"
                    '.NOTES'
                    "    Version       : $Version"
                    '#>'
                    '[CmdletBinding()]'
                    'param ()'
                    $Body
                    ''
                ) -join "`n"
            }

            function Write-GitRepository {
                # A repository whose main branch holds the given files in one commit.
                param ([hashtable]$File)
                $repository = Write-TestRepository -File $File
                Invoke-TestGit -Repository $repository -Argument 'init', '--quiet', '--initial-branch=main'
                Invoke-TestGit -Repository $repository -Argument 'add', '--all'
                Invoke-TestGit -Repository $repository -Argument 'commit', '--quiet', '--message', 'Base'
                $repository
            }

            function Write-TestFile {
                param ([string]$Repository, [string]$Name, [string]$Text)
                $target = Join-Path -Path $Repository -ChildPath $Name
                $null = New-Item -ItemType Directory -Path (Split-Path -Path $target -Parent) -Force
                [IO.File]::WriteAllText($target, $Text)
            }
        }

        It 'fails when the code changed and the Version did not, and names the script' {
            $repository = Write-GitRepository -File @{ 'Graph/Get-Thing.ps1' = (Get-ScriptText) }
            Write-TestFile -Repository $repository -Name 'Graph/Get-Thing.ps1' -Text (Get-ScriptText -Body "Write-Output 'two'")

            $result = Invoke-UnderTest @{ Path = $repository; Check = 'Version'; Base = 'main' }

            $result.ExitCode | Should -Be 1
            $result.Text | Should -Match 'Graph/Get-Thing\.ps1: the code changed, but Version is 1\.0\.0, and was 1\.0\.0'
            $result.Text | Should -Match 'Version\s+Failed'
        }

        It 'passes when the Version was raised with the code' {
            $repository = Write-GitRepository -File @{ 'Graph/Get-Thing.ps1' = (Get-ScriptText) }
            Write-TestFile -Repository $repository -Name 'Graph/Get-Thing.ps1' -Text (Get-ScriptText -Version '1.0.1' -Body "Write-Output 'two'")

            $result = Invoke-UnderTest @{ Path = $repository; Check = 'Version'; Base = 'main' }

            $result.ExitCode | Should -Be 0
            $result.Text | Should -Match '1 script\(s\) changed since main'
        }

        It 'fails when the Version went down' {
            $repository = Write-GitRepository -File @{ 'Graph/Get-Thing.ps1' = (Get-ScriptText -Version '1.2.0') }
            Write-TestFile -Repository $repository -Name 'Graph/Get-Thing.ps1' -Text (Get-ScriptText -Version '1.1.9' -Body "Write-Output 'two'")

            (Invoke-UnderTest @{ Path = $repository; Check = 'Version'; Base = 'main' }).ExitCode | Should -Be 1
        }

        It 'treats a change to comments and line endings alone as no change' {
            $repository = Write-GitRepository -File @{ 'Graph/Get-Thing.ps1' = (Get-ScriptText) }
            $text = (Get-ScriptText -Synopsis 'Does one thing, said better.') -replace "`n", "`r`n"
            Write-TestFile -Repository $repository -Name 'Graph/Get-Thing.ps1' -Text $text

            $result = Invoke-UnderTest @{ Path = $repository; Check = 'Version'; Base = 'main' }

            $result.ExitCode | Should -Be 0
            $result.Text | Should -Match 'No script''s code changed since main'
        }

        It 'counts a #Requires line as code' {
            $repository = Write-GitRepository -File @{ 'Graph/Get-Thing.ps1' = (Get-ScriptText) }
            Write-TestFile -Repository $repository -Name 'Graph/Get-Thing.ps1' -Text (Get-ScriptText -Requires '7.0')

            (Invoke-UnderTest @{ Path = $repository; Check = 'Version'; Base = 'main' }).ExitCode | Should -Be 1
        }

        It 'leaves test files and Templates/ out of the script rule' {
            $repository = Write-GitRepository -File @{
                'Graph/Get-Thing.Tests.ps1'     = (Get-ScriptText)
                'Templates/Script-Template.ps1' = (Get-ScriptText)
            }
            foreach ($name in 'Graph/Get-Thing.Tests.ps1', 'Templates/Script-Template.ps1') {
                Write-TestFile -Repository $repository -Name $name -Text (Get-ScriptText -Body "Write-Output 'two'")
            }

            (Invoke-UnderTest @{ Path = $repository; Check = 'Version'; Base = 'main' }).ExitCode | Should -Be 0
        }

        It 'fails on a new script that declares no Version, even before it is added to git' {
            $repository = Write-GitRepository -File @{ 'Graph/Get-Thing.ps1' = (Get-ScriptText) }
            Write-TestFile -Repository $repository -Name 'Standalone/New-Thing.ps1' -Text "[CmdletBinding()]`nparam ()`n"

            $result = Invoke-UnderTest @{ Path = $repository; Check = 'Version'; Base = 'main' }

            $result.ExitCode | Should -Be 1
            $result.Text | Should -Match 'Standalone/New-Thing\.ps1: new, and declares no Version'
        }

        It 'compares committed work with the commit its branch left, not with where the base is now' {
            $repository = Write-GitRepository -File @{
                'Graph/Get-Thing.ps1'   = (Get-ScriptText)
                'Graph/Get-Other.ps1'   = (Get-ScriptText)
            }
            Invoke-TestGit -Repository $repository -Argument 'switch', '--quiet', '--create', 'work'
            Write-TestFile -Repository $repository -Name 'Graph/Get-Thing.ps1' -Text (Get-ScriptText -Body "Write-Output 'two'")
            Invoke-TestGit -Repository $repository -Argument 'commit', '--quiet', '--all', '--message', 'Work'
            # main moves on with a change of its own, which is not this branch's to answer for.
            Invoke-TestGit -Repository $repository -Argument 'switch', '--quiet', 'main'
            Write-TestFile -Repository $repository -Name 'Graph/Get-Other.ps1' -Text (Get-ScriptText -Version '1.1.0' -Body "Write-Output 'three'")
            Invoke-TestGit -Repository $repository -Argument 'commit', '--quiet', '--all', '--message', 'Main'
            Invoke-TestGit -Repository $repository -Argument 'switch', '--quiet', 'work'

            $result = Invoke-UnderTest @{ Path = $repository; Check = 'Version'; Base = 'main' }

            $result.ExitCode | Should -Be 1
            $result.Text | Should -Match 'Graph/Get-Thing\.ps1: the code changed'
            $result.Text | Should -Not -Match 'Get-Other'
        }

        It 'fails when the code of a versioned region changed and its version did not, and passes once it is raised' {
            $template = {
                param ([string]$RegionVersion, [string]$Body)
                @(
                    "#region Block $RegionVersion - canonical copy in Templates/Block.ps1"
                    "function Get-Block { $Body }"
                    '#endregion Block'
                    ''
                ) -join "`n"
            }
            $repository = Write-GitRepository -File @{ 'Templates/Block.ps1' = (& $template '1.0.0' "'one'") }

            Write-TestFile -Repository $repository -Name 'Templates/Block.ps1' -Text (& $template '1.0.0' "'two'")
            $kept = Invoke-UnderTest @{ Path = $repository; Check = 'Version'; Base = 'main' }
            Write-TestFile -Repository $repository -Name 'Templates/Block.ps1' -Text (& $template '1.1.0' "'two'")
            $raised = Invoke-UnderTest @{ Path = $repository; Check = 'Version'; Base = 'main' }

            $kept.ExitCode | Should -Be 1
            $kept.Text | Should -Match 'Templates/Block\.ps1: the code of the Block region changed, but its version is 1\.0\.0'
            $raised.ExitCode | Should -Be 0
        }

        It 'says how to fix a base it cannot find' {
            $repository = Write-GitRepository -File @{ 'Graph/Get-Thing.ps1' = (Get-ScriptText) }

            $result = Invoke-UnderTest @{ Path = $repository; Check = 'Version'; Base = 'no-such-branch' }

            $result.ExitCode | Should -Be 1
            $result.Errors | Should -Match 'Version could not run: Cannot find where HEAD left ''no-such-branch''\. Fetch it'
        }
    }

    Context 'Scan' {

        It 'runs the repository''s own scanner over the repository' {
            $repository = Write-TestRepository -Folder 'Tools'
            Copy-Item -LiteralPath $script:ScannerPath -Destination (Join-Path -Path $repository -ChildPath 'Tools')
            $clean = Invoke-UnderTest @{ Path = $repository; Check = 'Scan' }

            # A GUID that is neither zeroed nor well known: the scanner's Guid rule.
            Set-Content -LiteralPath (Join-Path -Path $repository -ChildPath 'leak.txt') -Value ([guid]::NewGuid().ToString())
            $leak = Invoke-UnderTest @{ Path = $repository; Check = 'Scan' }

            $clean.ExitCode | Should -Be 0
            $leak.ExitCode | Should -Be 1
            $leak.Text | Should -Match 'leak\.txt'
            $leak.Text | Should -Match 'values masked'
            $leak.Warnings | Should -Match '1 finding'
        }
    }

    Context 'Reporting' {

        It 'runs every selected check after one fails, and says so in the summary' {
            $repository = Write-TestRepository -Bare 'Undocumented' -Folder 'Tools'
            Copy-Item -LiteralPath $script:ScannerPath -Destination (Join-Path -Path $repository -ChildPath 'Tools')

            $result = Invoke-UnderTest @{ Path = $repository; Check = 'Readme', 'Scan' }

            $result.ExitCode | Should -Be 1
            $result.Text | Should -Match 'Scan\s+Passed'
            $result.Text | Should -Match 'Readme\s+Failed'
        }

        It 'reports a check that cannot run as failed, and still runs the rest' {
            # Scan needs Tools/Test-SensitiveContent.ps1, which this repository does not have.
            $repository = Write-TestRepository

            $result = Invoke-UnderTest @{ Path = $repository; Check = 'Scan', 'Readme' }

            $result.ExitCode | Should -Be 1
            $result.Errors | Should -Match 'Scan could not run: No scanner'
            $result.Text | Should -Match 'Readme\s+Passed'
        }

        It 'returns exit code 1 to a caller that starts it with -File' {
            $repository = Write-TestRepository -Bare 'Undocumented'
            $folder = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('n'))
            $null = New-Item -ItemType Directory -Path $folder
            $stdin = Join-Path -Path $folder -ChildPath 'stdin.txt'
            [IO.File]::WriteAllText($stdin, '')

            # Start-Process joins arguments with spaces and quotes none of them.
            $arguments = '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $script:ScriptPath),
            '-Path', ('"{0}"' -f $repository), '-Check', 'Readme'
            $process = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $arguments -NoNewWindow -Wait -PassThru `
                -RedirectStandardInput $stdin -RedirectStandardOutput (Join-Path -Path $folder -ChildPath 'out.txt') `
                -RedirectStandardError (Join-Path -Path $folder -ChildPath 'err.txt')

            $process.ExitCode | Should -Be 1
        }
    }

    Context 'Selection' {

        It 'refuses Parse under PowerShell 7, before running anything' -Skip:($PSVersionTable.PSEdition -eq 'Desktop') {
            $repository = Write-TestRepository -Bare 'Undocumented'

            $result = Invoke-UnderTest @{ Path = $repository; Check = 'Readme', 'Parse' }

            $result.ExitCode | Should -Be 1
            $result.Errors | Should -Match 'Parse needs the Windows PowerShell parser'
            $result.Text | Should -Not -Match 'No README'
        }

        It 'refuses Analyzer under Windows PowerShell, before running anything' -Skip:($PSVersionTable.PSEdition -ne 'Desktop') {
            $repository = Write-TestRepository

            $result = Invoke-UnderTest @{ Path = $repository; Check = 'Analyzer' }

            $result.ExitCode | Should -Be 1
            $result.Errors | Should -Match 'Analyzer runs under PowerShell 7'
        }
    }

    Context 'Parse' -Skip:($PSVersionTable.PSEdition -ne 'Desktop') {

        It 'fails on PowerShell 7 syntax in a script that declares 5.1, and names the line' {
            $repository = Write-TestRepository -Folder 'Intune' -File @{
                'Intune/Test-Thing.ps1' = "#Requires -Version 5.1`n`$value = `$null`n`$other = `$value ?? 'default'`n"
            }

            $result = Invoke-UnderTest @{ Path = $repository; Check = 'Parse' }

            $result.ExitCode | Should -Be 1
            $result.Text | Should -Match 'Intune[\\/]Test-Thing\.ps1\(3\)'
        }

        It 'leaves a script that declares PowerShell 7 to the PowerShell 7 parser' {
            $repository = Write-TestRepository -Folder 'Graph' -File @{
                'Graph/Get-Thing.ps1' = "#Requires -Version 7.0`n`$value = `$null`n`$other = `$value ?? 'default'`n"
            }

            $result = Invoke-UnderTest @{ Path = $repository; Check = 'Parse' }

            $result.ExitCode | Should -Be 0
            $result.Text | Should -Match '0 script\(s\) declare 5\.1'
        }
    }
}

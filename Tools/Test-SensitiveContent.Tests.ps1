# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/zenpachi-alt/endpoint-engineering

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

<#
.SYNOPSIS
    Pester tests for Test-SensitiveContent.ps1.

.DESCRIPTION
    The scanner takes the folder above its own as the repository, so each test
    copies it into a small repository in Pester's TestDrive and runs the copy
    there. The real repository is never the subject.

    Every rule is tested both ways: with values it must report, and with the
    placeholders and public values it must let through. The rest covers what a
    finding holds, masking, which files are read, the two ways to allow a
    match, staged content, and the exit codes. The staged tests make their
    repository a git repository, so they need git; nothing is committed, so
    they need no committer.

    Every value a rule would report is put together at run time, so this file
    passes Tools/Test-SensitiveContent.ps1 like any other. The values it must
    let through are written out: the scanner lets them through here too.

.EXAMPLE
    Invoke-Pester -Path .\Tools\Test-SensitiveContent.Tests.ps1 -Output Detailed

.NOTES
    PowerShell    : 5.1 or later, matching the script under test.
    Graph scopes  : None.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : Pester 5.5.0 or later. git, for the staged tests.
#>

BeforeDiscovery {
    $guid = [guid]::NewGuid().ToString()
    $otherGuid = [guid]::NewGuid().ToString()
    $secret = 'Qw7rT9zL' + 'p2Xc5Vb8'
    $address = '10', '20', '30', '40' -join '.'
    $tenant = 'litware' + '.onmicrosoft.com'

    # One line each, and the rules that must report it.
    $script:Reported = @(
        @{ Name = 'a private key'; Rule = 'PrivateKey'; Severity = 'Error'; Line = '-----BEGIN ' + 'PRIVATE KEY-----' }
        @{ Name = 'an RSA private key'; Rule = 'PrivateKey'; Severity = 'Error'; Line = '-----BEGIN ' + 'RSA PRIVATE KEY-----' }
        @{ Name = 'an OpenSSH private key'; Rule = 'PrivateKey'; Severity = 'Error'; Line = '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----' }
        @{ Name = 'a JWT'; Rule = 'BearerToken'; Severity = 'Error'; Line = ('eyJ' + ('a' * 12)), ('b' * 12), ('c' * 12) -join '.' }
        @{ Name = 'a GitHub token'; Rule = 'ProviderToken'; Severity = 'Error'; Line = 'ghp_' + ('a1B2' * 9) }
        @{ Name = 'a fine-grained GitHub token'; Rule = 'ProviderToken'; Severity = 'Error'; Line = 'github_pat_' + ('a1B2_' * 5) }
        @{ Name = 'a Slack token'; Rule = 'ProviderToken'; Severity = 'Error'; Line = 'xoxb-' + '1234567890-abcdef' }
        @{ Name = 'a password assigned in PowerShell'; Rule = 'HardCodedSecret'; Severity = 'Error'; Line = '$Password = ''{0}''' -f $secret }
        @{ Name = 'a client secret assigned in double quotes'; Rule = 'HardCodedSecret'; Severity = 'Error'; Line = 'client_secret = "{0}"' -f $secret }
        @{ Name = 'an API key after a colon'; Rule = 'HardCodedSecret'; Severity = 'Error'; Line = 'apiKey: "{0}"' -f $secret }
        @{ Name = 'a connection string'; Rule = 'HardCodedSecret'; Severity = 'Error'; Line = 'ConnectionString = "{0}"' -f $secret }
        @{ Name = 'a client secret under a quoted JSON key'; Rule = 'HardCodedSecret'; Severity = 'Error'; Line = '"clientSecret": "{0}"' -f $secret }
        @{ Name = 'a password under a key in single quotes'; Rule = 'HardCodedSecret'; Severity = 'Error'; Line = "'password' = '{0}'" -f $secret }
        @{ Name = 'a GUID'; Rule = 'Guid'; Severity = 'Warning'; Line = "TenantId $guid" }
        @{ Name = 'a GUID in capitals'; Rule = 'Guid'; Severity = 'Warning'; Line = $guid.ToUpperInvariant() }
        @{ Name = 'a GUID in braces'; Rule = 'Guid'; Severity = 'Warning'; Line = "{$guid}" }
        @{ Name = 'a GUID between underscores'; Rule = 'Guid'; Severity = 'Warning'; Line = "policy_${guid}_assignment" }
        @{ Name = 'a GUID that follows a letter'; Rule = 'Guid'; Severity = 'Warning'; Line = "id$guid" }
        @{ Name = 'two GUIDs written back to back'; Rule = 'Guid', 'Guid'; Severity = 'Warning'; Line = "$guid$otherGuid" }
        @{ Name = 'an email address'; Rule = 'EmailOrUpn'; Severity = 'Warning'; Line = 'megan', 'litwareinc.com' -join '@' }
        @{ Name = 'an address in a domain that only ends like an allowed one'; Rule = 'EmailOrUpn'; Severity = 'Warning'
            Line = 'megan', 'notcontoso.com' -join '@'
        }
        @{ Name = 'a tenant domain'; Rule = 'TenantDomain'; Severity = 'Warning'; Line = "Connect to $tenant" }
        @{ Name = 'a UPN in a tenant domain'; Rule = 'EmailOrUpn', 'TenantDomain'; Severity = 'Warning'; Line = 'megan', $tenant -join '@' }
        @{ Name = 'a URL on a private host'; Rule = 'Url'; Severity = 'Warning'; Line = 'https://' + 'intranet.litwareinc.com/wiki' }
        @{ Name = 'a URL with a port'; Rule = 'Url'; Severity = 'Warning'; Line = 'http://' + 'deploy01.corp:8080/api' }
        @{ Name = 'a URL on a host that only ends like an allowed one'; Rule = 'Url'; Severity = 'Warning'
            Line = 'https://' + 'notmicrosoft.com/download'
        }
        @{ Name = 'a URL on an IP address'; Rule = 'IPAddress', 'Url'; Severity = 'Warning'; Line = 'http://' + $address + '/status' }
        @{ Name = 'a UNC path'; Rule = 'UncPath'; Severity = 'Warning'; Line = '\\' + 'fileserver01' + '\deploy$' }
        @{ Name = 'a private IP address'; Rule = 'IPAddress'; Severity = 'Warning'; Line = "Gateway $address" }
        @{ Name = 'a public IP address'; Rule = 'IPAddress'; Severity = 'Warning'; Line = '52', '164', '10', '7' -join '.' }
    )

    # One line each, which no rule may report.
    $script:Allowed = @(
        @{ Name = 'a secret placeholder in angle brackets'; Line = 'password = "<YourPassword>"' }
        @{ Name = 'a secret placeholder under a quoted JSON key'; Line = '"clientSecret": "<ClientSecret>"' }
        @{ Name = 'a secret read from the environment'; Line = '$Password = "$env:APP_PASSWORD"' }
        @{ Name = 'a secret read from a subexpression'; Line = 'client_secret = "$($Credential.Secret)"' }
        @{ Name = 'a secret marked as an example'; Line = 'api_key = "example-key-0001"' }
        @{ Name = 'a secret masked with asterisks'; Line = 'password = "********"' }
        @{ Name = 'a quoted value shorter than eight characters'; Line = 'pwd = "abc123"' }
        @{ Name = 'the zeroed GUID'; Line = '00000000-0000-0000-0000-000000000000' }
        @{ Name = 'a zeroed GUID with a counter'; Line = '00000000-0000-0000-0000-000000000012' }
        @{ Name = 'a GUID of one repeated letter'; Line = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' }
        @{ Name = 'a GUID of one repeated digit'; Line = '11111111-1111-1111-1111-111111111111' }
        @{ Name = 'the application ID of Microsoft Graph'; Line = '00000003-0000-0000-c000-000000000000' }
        @{ Name = 'a well-known application ID in capitals'; Line = '00000003-0000-0000-C000-000000000000' }
        @{ Name = 'an address at contoso.com'; Line = 'user@contoso.com' }
        @{ Name = 'an address under an allowed domain'; Line = 'user@mail.example.org' }
        @{ Name = 'an address under a reserved top-level domain'; Line = 'user@device.test' }
        @{ Name = 'the contoso tenant domain'; Line = 'contoso.onmicrosoft.com' }
        @{ Name = 'a Microsoft Learn URL'; Line = 'https://learn.microsoft.com/intune/' }
        @{ Name = 'a GitHub URL'; Line = 'https://github.com/PowerShell/PowerShell' }
        @{ Name = 'localhost with a port'; Line = 'http://localhost:8080/health' }
        @{ Name = 'a URL under a reserved top-level domain'; Line = 'https://intranet.example/wiki' }
        @{ Name = 'a UNC path on SERVER-001'; Line = '\\SERVER-001\Share' }
        @{ Name = 'a UNC path on a numbered placeholder host'; Line = '\\HOST-12\Share' }
        @{ Name = 'a UNC path on localhost'; Line = '\\localhost\c$' }
        @{ Name = 'the loopback address'; Line = '127.0.0.1' }
        @{ Name = 'a subnet mask'; Line = '255.255.255.0' }
        @{ Name = 'an address in 192.0.2.0/24'; Line = '192.0.2.10' }
        @{ Name = 'an address in 198.51.100.0/24'; Line = '198.51.100.7' }
        @{ Name = 'an address in 203.0.113.0/24'; Line = '203.0.113.25' }
        @{ Name = 'a link-local address'; Line = '169.254.10.20' }
        @{ Name = 'a Windows build number'; Line = 'Windows 10.0.19041.1' }
        @{ Name = 'a version number with a part above 255'; Line = 'Version 2.41.300.0' }
    )
}

BeforeAll {
    $script:ScannerPath = Join-Path -Path $PSScriptRoot -ChildPath 'Test-SensitiveContent.ps1'
    $script:PowerShellPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

    # Neither zeroed nor well known: the Guid rule reports them.
    $script:Guid = [guid]::NewGuid().ToString()
    $script:OtherGuid = [guid]::NewGuid().ToString()

    function Write-TestRepository {
        # A repository root holding a copy of the scanner under Tools, and the given files, one line per item.
        param ([hashtable]$File = @{})
        $root = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('n'))
        $tools = Join-Path -Path $root -ChildPath 'Tools'
        $null = New-Item -ItemType Directory -Path $tools
        Copy-Item -LiteralPath $script:ScannerPath -Destination $tools
        foreach ($relative in $File.Keys) {
            $target = Join-Path -Path $root -ChildPath $relative
            $null = New-Item -ItemType Directory -Path (Split-Path -Path $target -Parent) -Force
            [IO.File]::WriteAllText($target, (@($File[$relative]) -join "`n") + "`n")
        }
        $root
    }

    function Invoke-Scanner {
        # The copy of the scanner in a test repository. Warnings and errors are captured, so they stay out of the test log.
        param ([string]$Repository, [hashtable]$Parameters = @{})
        $scanner = Join-Path -Path $Repository -ChildPath 'Tools/Test-SensitiveContent.ps1'
        $all = @(& $scanner @Parameters 3>&1 2>&1)
        $exitCode = $LASTEXITCODE
        [pscustomobject]@{
            Findings = @($all | Where-Object {
                    $_ -isnot [System.Management.Automation.ErrorRecord] -and
                    $_ -isnot [System.Management.Automation.WarningRecord]
                })
            Warnings = (@($all | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object Message) -join "`n")
            Errors   = (@($all | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | ForEach-Object { "$_" }) -join "`n")
            ExitCode = $exitCode
        }
    }

    function Invoke-LineScan {
        # One file holding the given lines, scanned in a repository of its own.
        param ([string[]]$Line, [hashtable]$Parameters = @{})
        $repository = Write-TestRepository -File @{ 'Content/sample.txt' = $Line }
        Invoke-Scanner -Repository $repository -Parameters $Parameters
    }

    function Invoke-TestGit {
        # Git in a test repository. Windows PowerShell turns git's standard error into error records,
        # which 'Stop' would throw on.
        param ([string]$Repository, [string[]]$Argument)
        $ErrorActionPreference = 'Continue'
        $output = & git -C $Repository -c core.autocrlf=false @Argument 2>&1
        if ($LASTEXITCODE -ne 0) { throw ('git {0} failed: {1}' -f ($Argument -join ' '), ($output -join ' ')) }
    }
}

Describe 'Test-SensitiveContent' {

    Context 'Rules' {

        It 'reports <Name>' -ForEach $script:Reported {
            $result = Invoke-LineScan -Line $Line

            $result.ExitCode | Should -Be 1
            @($result.Findings | ForEach-Object Rule | Sort-Object) | Should -Be @($Rule | Sort-Object)
            @($result.Findings | ForEach-Object Severity | Sort-Object -Unique) | Should -Be $Severity
        }

        It 'lets through <Name>' -ForEach $script:Allowed {
            $result = Invoke-LineScan -Line $Line

            $result.ExitCode | Should -Be 0
            $result.Findings | Should -BeNullOrEmpty
        }
    }

    Context 'Findings' {

        It 'names the file with forward slashes, the line, the rule, and what to do about it' {
            $repository = Write-TestRepository -File @{ 'Content/Sub/sample.txt' = 'first line', '', "id $script:Guid" }

            $result = Invoke-Scanner -Repository $repository

            $result.Findings.Count | Should -Be 1
            $result.Findings[0].File | Should -Be 'Content/Sub/sample.txt'
            $result.Findings[0].Line | Should -Be 3
            $result.Findings[0].Rule | Should -Be 'Guid'
            $result.Findings[0].Severity | Should -Be 'Warning'
            $result.Findings[0].Advice | Should -Match 'zeroed placeholder'
        }

        It 'reports every match on a line' {
            $result = Invoke-LineScan -Line "from $script:Guid to $script:OtherGuid"

            $result.Findings.Count | Should -Be 2
            @($result.Findings | ForEach-Object Line) | Should -Be 1, 1
        }

        It 'puts findings at Error severity first' {
            $result = Invoke-LineScan -Line "id $script:Guid", ('-----BEGIN ' + 'PRIVATE KEY-----')

            @($result.Findings | ForEach-Object Rule) | Should -Be 'PrivateKey', 'Guid'
            @($result.Findings | ForEach-Object Line) | Should -Be 2, 1
        }

        It 'counts the findings, the files and the errors in a warning' {
            $repository = Write-TestRepository -File @{
                'Content/sample.txt' = "id $script:Guid", ('-----BEGIN ' + 'PRIVATE KEY-----')
                'Content/clean.txt'  = 'nothing to report'
            }

            $result = Invoke-Scanner -Repository $repository -Parameters @{ Path = Join-Path -Path $repository -ChildPath 'Content' }

            $result.Warnings | Should -Match '2 finding\(s\) in 2 scanned file\(s\); 1 at Error severity'
        }
    }

    Context 'Masking' {

        It 'shows the first four characters, the last two and the length' {
            $result = Invoke-LineScan -Line "id $script:Guid"

            $result.Findings[0].Match |
                Should -Be ('{0}...{1} (36 chars)' -f $script:Guid.Substring(0, 4), $script:Guid.Substring(34))
        }

        It 'shows them of a value of 24 characters, where they are a quarter of it' {
            $result = Invoke-LineScan -Line (('m' * 9), 'litwareinc.com' -join '@')

            $result.Findings[0].Match | Should -Be 'mmmm...om (24 chars)'
        }

        It 'shows asterisks only for a value of 23 characters' {
            $result = Invoke-LineScan -Line (('m' * 8), 'litwareinc.com' -join '@')

            $result.Findings[0].Match | Should -Be ('*' * 23)
        }

        It 'keeps the value out of everything it writes' {
            $result = Invoke-LineScan -Line "id $script:Guid"

            $written = ($result.Findings | Out-String), $result.Warnings, $result.Errors -join "`n"
            $written | Should -Not -Match ([regex]::Escape($script:Guid))
            $result.Warnings | Should -Match 'Values are masked'
        }

        It 'shows asterisks only for an IP address, whatever its length' -ForEach @(
            @{ Octet = '10', '1', '2', '3' }
            @{ Octet = '192', '168', '100', '200' }
        ) {
            $address = $Octet -join '.'

            $result = Invoke-LineScan -Line $address

            $result.Findings[0].Match | Should -Be ('*' * $address.Length)
        }

        It 'shows the value with -ShowMatch' {
            $result = Invoke-LineScan -Line "id $script:Guid" -Parameters @{ ShowMatch = $true }

            $result.Findings[0].Match | Should -Be $script:Guid
        }
    }

    Context 'Files' {

        It 'scans the repository it sits in when given no path' {
            $repository = Write-TestRepository -File @{ 'notes.txt' = "id $script:Guid" }

            $result = Invoke-Scanner -Repository $repository

            @($result.Findings | ForEach-Object File) | Should -Be 'notes.txt'
        }

        It 'scans only the folders and files that -Path names' {
            $repository = Write-TestRepository -File @{
                'Content/a.txt' = "id $script:Guid"
                'Other/b.txt'   = "id $script:Guid"
                'Other/c.txt'   = "id $script:Guid"
            }
            $path = (Join-Path -Path $repository -ChildPath 'Content'), (Join-Path -Path $repository -ChildPath 'Other/b.txt')

            $result = Invoke-Scanner -Repository $repository -Parameters @{ Path = $path }

            @($result.Findings | ForEach-Object File | Sort-Object) | Should -Be 'Content/a.txt', 'Other/b.txt'
        }

        It 'reads a file whose name starts with a dot' {
            # Hidden on Linux and macOS, where the checks run too.
            $repository = Write-TestRepository -File @{ '.settings' = "id $script:Guid" }

            $result = Invoke-Scanner -Repository $repository

            @($result.Findings | ForEach-Object File) | Should -Be '.settings'
        }

        It 'passes over everything under .git' {
            $repository = Write-TestRepository -File @{ '.git/notes.txt' = "id $script:Guid" }

            (Invoke-Scanner -Repository $repository).ExitCode | Should -Be 0
        }

        It 'passes over a file with a binary extension' {
            $repository = Write-TestRepository -File @{ 'Content/logo.png' = "id $script:Guid" }

            (Invoke-Scanner -Repository $repository).ExitCode | Should -Be 0
        }

        It 'passes over a file above -MaximumFileSizeBytes, and says so' {
            $repository = Write-TestRepository -File @{ 'Content/big.txt' = "id $script:Guid", ('x' * 3000) }

            $result = Invoke-Scanner -Repository $repository -Parameters @{ MaximumFileSizeBytes = 1024 }

            $result.ExitCode | Should -Be 0
            $result.Warnings | Should -Match "Skipped 'Content/big\.txt': \d+ bytes exceeds the 1024 byte limit"
        }

        It 'passes over files that match -ExcludePath, written with <Slash>' -ForEach @(
            @{ Slash = 'forward slashes'; Pattern = 'Content/Export/*' }
            @{ Slash = 'backslashes'; Pattern = 'Content\Export\*' }
        ) {
            $repository = Write-TestRepository -File @{
                'Content/Export/devices.txt' = "id $script:Guid"
                'Content/kept.txt'           = "id $script:Guid"
            }

            $result = Invoke-Scanner -Repository $repository -Parameters @{ ExcludePath = $Pattern }

            @($result.Findings | ForEach-Object File) | Should -Be 'Content/kept.txt'
        }
    }

    Context 'Allowing a match' {

        It 'passes over a line that carries the allow marker, and no other line' {
            $result = Invoke-LineScan -Line "id $script:Guid  # sensitive-content:allow", "id $script:OtherGuid"

            $result.Findings.Count | Should -Be 1
            $result.Findings[0].Line | Should -Be 2
        }

        It 'lets through a match that fits -AllowPattern, and no other match' {
            $kept = 'megan', 'proseware.com' -join '@'
            $line = ('megan', 'litwareinc.com' -join '@'), $kept

            $result = Invoke-LineScan -Line $line -Parameters @{ AllowPattern = 'litwareinc\.com$'; ShowMatch = $true }

            @($result.Findings | ForEach-Object Match) | Should -Be $kept
        }
    }

    Context 'Staged content' {

        It 'scans what is staged, not what is on disk' {
            $repository = Write-TestRepository -File @{ 'Content/sample.txt' = 'first line', "id $script:Guid" }
            Invoke-TestGit -Repository $repository -Argument 'init', '--quiet'
            Invoke-TestGit -Repository $repository -Argument 'add', '--', 'Content/sample.txt'
            # Cleaned up on disk after staging: the commit would still carry the identifier.
            [IO.File]::WriteAllText((Join-Path -Path $repository -ChildPath 'Content/sample.txt'), "nothing to report`n")

            $result = Invoke-Scanner -Repository $repository -Parameters @{ Staged = $true }

            $result.ExitCode | Should -Be 1
            $result.Findings.Count | Should -Be 1
            $result.Findings[0].File | Should -Be 'Content/sample.txt'
            $result.Findings[0].Line | Should -Be 2
        }

        It 'passes over what is on disk and not staged' {
            $repository = Write-TestRepository -File @{
                'Content/staged.txt'   = 'nothing to report'
                'Content/unstaged.txt' = "id $script:Guid"
            }
            Invoke-TestGit -Repository $repository -Argument 'init', '--quiet'
            Invoke-TestGit -Repository $repository -Argument 'add', '--', 'Content/staged.txt'
            # Added on disk after staging: the commit would not carry it.
            [IO.File]::WriteAllText((Join-Path -Path $repository -ChildPath 'Content/staged.txt'), "id $script:Guid`n")

            $result = Invoke-Scanner -Repository $repository -Parameters @{ Staged = $true }

            $result.ExitCode | Should -Be 0
            $result.Findings | Should -BeNullOrEmpty
        }

        It 'scans a staged file whose name has a character outside ASCII' {
            # git writes such a name in quotes, with its bytes escaped, unless asked not to.
            $name = 'Content/caf{0}.txt' -f [char]0xE9
            $repository = Write-TestRepository -File @{ $name = "id $script:Guid" }
            Invoke-TestGit -Repository $repository -Argument 'init', '--quiet'
            Invoke-TestGit -Repository $repository -Argument 'add', '--', $name

            $result = Invoke-Scanner -Repository $repository -Parameters @{ Staged = $true }

            $result.ExitCode | Should -Be 1
            @($result.Findings | ForEach-Object File) | Should -Be $name
        }

        It 'exits 2 and names a staged file it cannot read, rather than passing over it' {
            $repository = Write-TestRepository
            Invoke-TestGit -Repository $repository -Argument 'init', '--quiet'
            # A submodule entry: staged, and with no content of its own to show.
            Invoke-TestGit -Repository $repository -Argument 'update-index', '--add', '--cacheinfo', ('160000,{0},Vendor/module' -f ('1' * 40))

            $result = Invoke-Scanner -Repository $repository -Parameters @{ Staged = $true }
            $excluded = Invoke-Scanner -Repository $repository -Parameters @{ Staged = $true; ExcludePath = 'Vendor/*' }

            $result.ExitCode | Should -Be 2
            $result.Errors | Should -Match "Scan failed: The staged content of 'Vendor/module' could not be read"
            $excluded.ExitCode | Should -Be 0
        }

        It 'exits 2 and says why outside a git repository' {
            $repository = Write-TestRepository
            # Stops git looking for a repository above TestDrive.
            $ceiling = $env:GIT_CEILING_DIRECTORIES
            $env:GIT_CEILING_DIRECTORIES = Split-Path -Path $repository -Parent
            try {
                $result = Invoke-Scanner -Repository $repository -Parameters @{ Staged = $true }
            }
            finally {
                $env:GIT_CEILING_DIRECTORIES = $ceiling
            }

            $result.ExitCode | Should -Be 2
            $result.Errors | Should -Match 'Scan failed: The staged files could not be listed\. Is this a git repository\?'
        }
    }

    Context 'Exit codes' {

        It 'exits 0 and writes nothing when there is nothing to report' {
            $result = Invoke-LineScan -Line 'nothing to report'

            $result.ExitCode | Should -Be 0
            $result.Findings | Should -BeNullOrEmpty
            $result.Warnings | Should -BeNullOrEmpty
            $result.Errors | Should -BeNullOrEmpty
        }

        It 'exits 2 and says why when the scan cannot run' {
            $repository = Write-TestRepository

            $result = Invoke-Scanner -Repository $repository -Parameters @{ Path = Join-Path -Path $repository -ChildPath 'Missing' }

            $result.ExitCode | Should -Be 2
            $result.Errors | Should -Match 'Scan failed: .*Missing'
            $result.Findings | Should -BeNullOrEmpty
        }

        It 'returns exit code <Expected> to a caller that starts it with -File, as the pre-commit hook does, <When>' -ForEach @(
            @{ Expected = 0; When = 'when it finds nothing' }
            @{ Expected = 1; When = 'when it finds something' }
            @{ Expected = 2; When = 'when it cannot run' }
        ) {
            $line = if ($Expected -eq 1) { "id $script:Guid" } else { 'nothing to report' }
            $repository = Write-TestRepository -File @{ 'Content/sample.txt' = $line }
            $scanner = Join-Path -Path $repository -ChildPath 'Tools/Test-SensitiveContent.ps1'
            $target = Join-Path -Path $repository -ChildPath $(if ($Expected -eq 2) { 'Missing' } else { 'Content' })
            $stdin = Join-Path -Path $repository -ChildPath 'stdin.txt'
            [IO.File]::WriteAllText($stdin, '')

            # Start-Process joins arguments with spaces and quotes none of them.
            $arguments = '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $scanner),
            '-Path', ('"{0}"' -f $target)
            $process = Start-Process -FilePath $script:PowerShellPath -ArgumentList $arguments -NoNewWindow -Wait -PassThru `
                -RedirectStandardInput $stdin -RedirectStandardOutput (Join-Path -Path $repository -ChildPath 'out.txt') `
                -RedirectStandardError (Join-Path -Path $repository -ChildPath 'err.txt')

            $process.ExitCode | Should -Be $Expected
        }
    }
}

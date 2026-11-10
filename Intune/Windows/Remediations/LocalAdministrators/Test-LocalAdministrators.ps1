# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/zenpachi-alt/endpoint-engineering

#Requires -Version 5.1

<#
.SYNOPSIS
    Reports the members of this device's local Administrators group, and flags
    the device when a member is not built in and not on the allow-list.

.DESCRIPTION
    Detection-only script package: there is no remediation script. Membership
    of the local Administrators group is enforced with Intune's own policy
    (Endpoint security > Account protection > Local user group membership).
    This package answers the two questions that policy does not: what is in
    the group before the policy is enforced, and what has drifted since.

    The group is found by its SID, S-1-5-32-544, so the script works in every
    display language. Each member is sorted by its SID alone, which needs no
    network and no directory:

      BuiltInAdministrator  The device's own account with RID 500. Always
                            expected.
      LocalAccount          Another account of this device. Expected when its
                            name is in AllowedLocalAccountName.
      EntraPrincipal        A Microsoft Entra user, group or role
                            (S-1-12-1-...). Expected when its SID is in
                            AllowedSid.
      DomainAdmins          The Domain Admins group of an Active Directory
                            domain (RID 512). Always expected: Windows adds it
                            when a device joins a domain.
      DomainPrincipal       Any other domain account or group. Expected when
                            its SID is in AllowedSid.
      Other                 Anything else, such as a well-known group.
                            Expected when its SID is in AllowedSid.

    A SID cannot say whether an Entra member is a user, a group or a role, and
    the SIDs of the two roles Windows adds on Entra join (Global Administrator
    and the device local administrator role) differ in every tenant. So the
    package runs in two modes:

      Inventory  Lists every member and always exits 0. Deploy this first, and
                 read the SIDs your tenant uses from the output.
      Detect     Exits 1 when a member is neither built in nor allowed.

    Intune runs the script without parameters, so the mode and the allow-list
    are the parameter defaults: set them in your own copy before deploying it.
    Keep that copy out of any public repository, because the SIDs identify
    your tenant.

    A member's name is shown where Windows can resolve it. An Entra role or
    group has no name on a device, and a domain account has none while no
    domain controller can be reached, so a missing name does not mean the
    account is gone. The verdict never depends on the name of anything but a
    local account.

    The output line starts with a token, for filtering an export:
      Inventory   Inventory mode. Every member, those not allowed first.
      Expected    Detect mode. Every member is built in or allowed.
      Unexpected  Detect mode. The members that are not allowed.

    The package has no remediation, so exit 1 starts nothing. It puts the
    device under "With issues" in the report:
      exit 0  Inventory, or Expected.
      exit 1  Unexpected.
      exit 2  The check could not be completed.

.PARAMETER Mode
    Inventory lists the members and never flags the device. Detect flags the
    device when a member is not allowed. Set the default in your copy.

.PARAMETER AllowedSid
    SIDs that are expected in the group, whatever they belong to. Several can
    be given as an array or as one comma-separated string, so the parameter
    also works with powershell.exe -File. Set the default in your copy.

.PARAMETER AllowedLocalAccountName
    Names of local accounts that are expected in the group, without the device
    name: for example the account a Windows LAPS policy creates and manages.
    A local account has a different SID on every device, so it is allowed by
    name. Set the default in your copy.

.PARAMETER LogDirectory
    Directory for the script log. Defaults to
    %ProgramData%\EndpointEngineering\Logs, which is writable by SYSTEM and
    readable by support staff.

.PARAMETER MaxLogSizeBytes
    Size at which the log is rotated to a single .old copy.

.EXAMPLE
    .\Test-LocalAdministrators.ps1 -Verbose

    Lists this device's local administrators and echoes every log line to the
    console. It only reads, so it needs no administrator rights.

.EXAMPLE
    .\Test-LocalAdministrators.ps1 -Mode Detect -AllowedSid '<RoleSid1>', '<RoleSid2>' -AllowedLocalAccountName 'LapsAdmin'

    Tries an allow-list on one device before the defaults are set and the
    package is deployed. Exit code 1 means a member is not allowed.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.0.0
    Last updated  : 2026-11-10

    PowerShell    : Windows PowerShell 5.1 only. PowerShell 7 has to be
                    deployed separately and cannot be assumed on a device.
    Context       : SYSTEM under Intune (Run this script using the logged-on
                    credentials: No). Any user when run by hand: it only reads.
    Host          : 32-bit or 64-bit. Nothing it reads is redirected.
    Encoding      : UTF-8. Use UTF-8 without BOM if "Enforce script signature
                    check" is enabled. The file is ASCII-only.
    Modules       : None. The group is read through ADSI and the device's
                    accounts through CIM, which both ship with Windows.
                    Get-LocalGroupMember is not used: it fails when the group
                    holds a member it cannot resolve.
    Licensing     : Remediations require Windows Enterprise E3/E5, Windows
                    Education A3/A5, or Windows VDA per user, plus Intune.
    Graph scopes  : None (runs on the device, not against Graph).
    Admin consent : Not applicable.

    Output        : The output line and the log name accounts and SIDs of the
                    device and the tenant. Treat an export as tenant data.

.LINK
    https://learn.microsoft.com/entra/identity/devices/assign-local-admin

.LINK
    https://learn.microsoft.com/intune/device-configuration/endpoint-security/account-protection
#>

[CmdletBinding()]
param (
    [Parameter()]
    [ValidateSet('Inventory', 'Detect')]
    [string]$Mode = 'Inventory',

    [Parameter()]
    [AllowEmptyCollection()]
    [string[]]$AllowedSid = @(),

    [Parameter()]
    [AllowEmptyCollection()]
    [string[]]$AllowedLocalAccountName = @(),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$LogDirectory = (Join-Path -Path $env:ProgramData -ChildPath 'EndpointEngineering\Logs'),

    [Parameter()]
    [ValidateRange(65536, 104857600)]
    [int]$MaxLogSizeBytes = 1048576
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Exit codes are part of the Intune contract - do not repurpose them.
$ExitIssueNotFound = 0
$ExitIssueFound = 1
$ExitError = 2

# Set by Initialize-LogFile. $null means "log to the verbose stream only".
$script:LogFile = $null

function Initialize-LogFile {
    <#
        .SYNOPSIS
            Creates the log directory, rotates an oversized log, and returns the
            log file path. Returns $null if logging is not possible, so that a
            logging problem never fails the detection.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Directory,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory)]
        [int]$MaxSizeBytes
    )

    try {
        if (-not (Test-Path -LiteralPath $Directory)) {
            $null = New-Item -Path $Directory -ItemType Directory -Force -ErrorAction Stop
        }

        $path = Join-Path -Path $Directory -ChildPath "$Name.log"

        if (Test-Path -LiteralPath $path) {
            $existing = Get-Item -LiteralPath $path -ErrorAction Stop
            if ($existing.Length -gt $MaxSizeBytes) {
                Move-Item -LiteralPath $path -Destination "$path.old" -Force -ErrorAction Stop
            }
        }

        return $path
    }
    catch {
        Write-Warning "Could not initialise log file in '$Directory': $($_.Exception.Message). Continuing without a log file."
        return $null
    }
}

function Write-LogEntry {
    <#
        .SYNOPSIS
            Appends a timestamped line to the log file and the verbose stream.
            Never writes to STDOUT: that stream carries the detection result.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter()]
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $line = '{0} [{1}] [PID {2}] {3}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff zzz', [cultureinfo]::InvariantCulture), $Level, $PID, $Message

    if ($script:LogFile) {
        try {
            Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 -ErrorAction Stop
        }
        catch {
            # Disable logging rather than fail the run, and say so once.
            $script:LogFile = $null
            Write-Warning "Logging stopped: $($_.Exception.Message)"
        }
    }

    Write-Verbose $line
}

function Write-ResultLine {
    <#
        .SYNOPSIS
            Writes the single STDOUT line Intune surfaces in the console,
            truncated to the 2048-character output limit.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Message
    )

    if ($Message.Length -gt 2048) {
        $Message = $Message.Substring(0, 2045) + '...'
    }

    Write-Output $Message
}

function ConvertTo-AllowList {
    <#
        .SYNOPSIS
            Returns the entries of an allow-list parameter, one each: a
            comma-separated string is split, and blanks are dropped.

        .DESCRIPTION
            powershell.exe -File hands 'a,b' to an array parameter as one
            string. Neither a SID nor a Windows account name can contain a
            comma, so splitting on it loses nothing.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Value
    )

    foreach ($item in @($Value)) {
        foreach ($part in ([string]$item -split ',')) {
            $entry = $part.Trim()
            if ($entry) { $entry }
        }
    }
}

function ConvertTo-SidText {
    <#
        .SYNOPSIS
            Returns a SID in the form Windows writes it, or throws when the
            text is not a SID, so a mistyped allow-list fails the check
            instead of quietly allowing nothing.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Value
    )

    try {
        $sid = ([System.Security.Principal.SecurityIdentifier]::new($Value)).Value
    }
    catch {
        throw ("'$Value' in AllowedSid is not a SID. A SID looks like S-1-5-21-..., or S-1-12-1-... for a " +
            'Microsoft Entra user, group or role.')
    }

    # Windows does not refuse a number too large for a SID: it reads it as the
    # largest one, which would leave an entry that matches nothing.
    if ($sid -ne $Value) {
        throw "'$Value' in AllowedSid is not a SID Windows can hold: it reads it as '$sid'. Check the entry for a mistyped number."
    }

    return $sid
}

function Get-MachineSid {
    <#
        .SYNOPSIS
            Returns the SID every account of this device starts with, read
            from the built-in Administrator account, whatever it is named.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param ()

    # LocalAccount = TRUE keeps the query on the device. Without it, a
    # domain-joined device asks the domain for every account it has.
    $accounts = @(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount = TRUE' -ErrorAction Stop)
    $builtIn = @($accounts | Where-Object { [string]$_.SID -match '^S-1-5-21-\d+-\d+-\d+-500$' })

    if ($builtIn.Count -ne 1) {
        throw "Expected one local account with RID 500 to read the machine SID from, and found $($builtIn.Count)."
    }

    return ([string]$builtIn[0].SID) -replace '-500$', ''
}

function Get-AdministratorsGroupMember {
    <#
        .SYNOPSIS
            Returns the SID of every member of the local Administrators group,
            with its name where Windows can resolve one.

        .DESCRIPTION
            Read through ADSI, which returns a member it cannot resolve as its
            SID. Get-LocalGroupMember fails on such a member, and an Entra
            joined device always has some: the two Entra roles added at join
            have no name on the device.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param ()

    # The group's name is translated with Windows; its SID never changes.
    $groupSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $groupName = ($groupSid.Translate([System.Security.Principal.NTAccount]).Value -split '\\')[-1]

    $group = [ADSI]"WinNT://./$groupName,group"
    $members = @($group.psbase.Invoke('Members'))

    foreach ($member in $members) {
        $bytes = $member.GetType().InvokeMember('objectSid', [System.Reflection.BindingFlags]::GetProperty, $null, $member, $null)
        if ($null -eq $bytes) { throw "A member of the '$groupName' group returned no SID." }
        $sid = [System.Security.Principal.SecurityIdentifier]::new([byte[]]$bytes, 0)

        # No name is not a failure: an Entra role or group has none on a
        # device, and a domain account has none while no domain controller
        # answers. The caller reports the member by its SID.
        $name = ''
        try {
            $name = $sid.Translate([System.Security.Principal.NTAccount]).Value
        }
        catch {
            $name = ''
        }

        [pscustomobject]@{
            Sid  = $sid.Value
            Name = $name
        }
    }
}

function Get-MemberKind {
    <#
        .SYNOPSIS
            Says what a member is, from its SID and the device's own. Reads no
            state.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Sid,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$MachineSid
    )

    if ($Sid -eq "$MachineSid-500") { return 'BuiltInAdministrator' }
    if ($Sid -like "$MachineSid-*") { return 'LocalAccount' }
    if ($Sid -like 'S-1-12-1-*') { return 'EntraPrincipal' }
    if ($Sid -match '^S-1-5-21-\d+-\d+-\d+-512$') { return 'DomainAdmins' }
    if ($Sid -like 'S-1-5-21-*') { return 'DomainPrincipal' }
    return 'Other'
}

function Get-AdministratorsVerdict {
    <#
        .SYNOPSIS
            Decides which members are expected, and returns the token, exit
            code and detail to report. Reads no state, so every combination
            can be tested without a device.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Member,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$MachineSid,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$AllowedSid,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$AllowedLocalAccountName,

        [Parameter(Mandatory)]
        [ValidateSet('Inventory', 'Detect')]
        [string]$Mode
    )

    $sidSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $AllowedSid) { $null = $sidSet.Add($entry) }

    $nameSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $AllowedLocalAccountName) { $null = $nameSet.Add($entry) }

    $rated = @(foreach ($item in $Member) {
            $sid = [string]$item.Sid
            $name = [string]$item.Name
            $kind = Get-MemberKind -Sid $sid -MachineSid $MachineSid

            # 'DEVICE\name' or 'DOMAIN\name': the part after the backslash.
            $leaf = ($name -split '\\')[-1]

            $reason = if ($kind -eq 'BuiltInAdministrator') { 'built in' }
            elseif ($kind -eq 'DomainAdmins') { 'added by the domain join' }
            elseif ($sidSet.Contains($sid)) { 'SID allowed' }
            elseif ($kind -eq 'LocalAccount' -and $leaf -and $nameSet.Contains($leaf)) { 'name allowed' }
            else { '' }

            $text = if ($name) { "$name ($sid, $kind)" } else { "$sid ($kind, no name on this device)" }

            [pscustomobject]@{
                Sid        = $sid
                Name       = $name
                Kind       = $kind
                IsExpected = [bool]$reason
                Reason     = $reason
                Text       = $text
            }
        })

    $notAllowed = @($rated | Where-Object { -not $_.IsExpected })
    $allowed = @($rated | Where-Object { $_.IsExpected })
    $notAllowedText = if ($notAllowed.Count -gt 0) { @($notAllowed | ForEach-Object { $_.Text }) -join '; ' } else { 'none' }
    $allowedText = if ($allowed.Count -gt 0) { @($allowed | ForEach-Object { $_.Text }) -join '; ' } else { 'none' }

    if ($Mode -eq 'Inventory') {
        $token = 'Inventory'
        $exitCode = 0
        # Those not allowed come first: Intune keeps 2048 characters.
        $detail = "$($rated.Count) member(s). Not allowed: $notAllowedText. Built in or allowed: $allowedText."
    }
    elseif ($notAllowed.Count -gt 0) {
        $token = 'Unexpected'
        $exitCode = 1
        $detail = "$($notAllowed.Count) of $($rated.Count) member(s) are not allowed: $notAllowedText."
    }
    elseif ($rated.Count -eq 0) {
        $token = 'Expected'
        $exitCode = 0
        $detail = 'the group has no members.'
    }
    else {
        $token = 'Expected'
        $exitCode = 0
        $detail = "all $($rated.Count) member(s) are built in or allowed."
    }

    return [pscustomobject]@{
        Token    = $token
        ExitCode = $exitCode
        Detail   = $detail
        Members  = $rated
    }
}

try {
    $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
    $script:LogFile = Initialize-LogFile -Directory $LogDirectory -Name $scriptName -MaxSizeBytes $MaxLogSizeBytes

    Write-LogEntry -Message "Detection started. Mode: $Mode. Host: $(if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' }); OS: $(if ([Environment]::Is64BitOperatingSystem) { '64-bit' } else { '32-bit' }); user: $([Environment]::UserName)."

    #region Detect
    # The defaults are edited by hand and are not checked when they bind, so
    # they are checked here, where a mistake exits 2.
    if ($Mode -ne 'Inventory' -and $Mode -ne 'Detect') {
        throw "Mode is '$Mode'. It must be Inventory or Detect."
    }

    $allowedSids = @(ConvertTo-AllowList -Value $AllowedSid | ForEach-Object { ConvertTo-SidText -Value $_ })
    $allowedNames = @(ConvertTo-AllowList -Value $AllowedLocalAccountName)
    Write-LogEntry -Message "Allow-list: $($allowedSids.Count) SID(s), $($allowedNames.Count) local account name(s)."

    $machineSid = [string](Get-MachineSid)
    if ($machineSid -notmatch '^S-1-5-21-\d+-\d+-\d+$') {
        throw "Could not read the machine SID (got '$machineSid')."
    }

    $members = @(Get-AdministratorsGroupMember)
    $verdict = Get-AdministratorsVerdict -Member $members -MachineSid $machineSid -AllowedSid $allowedSids `
        -AllowedLocalAccountName $allowedNames -Mode $Mode

    foreach ($entry in $verdict.Members) {
        if ($entry.IsExpected) {
            Write-LogEntry -Message "Member $($entry.Text): expected, $($entry.Reason)."
        }
        else {
            Write-LogEntry -Message "Member $($entry.Text): not allowed." -Level WARN
        }
    }
    #endregion

    $line = "$($verdict.Token): $($verdict.Detail)"
    Write-LogEntry -Message $line -Level $(if ($verdict.ExitCode -eq 0) { 'INFO' } else { 'WARN' })
    Write-ResultLine -Message $line
    exit $(if ($verdict.ExitCode -eq 0) { $ExitIssueNotFound } else { $ExitIssueFound })
}
catch {
    $message = "Detection failed: $($_.Exception.Message)"
    Write-LogEntry -Message "$message Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" -Level ERROR

    # Continue, not Stop: this error must not escape and turn into exit code 1,
    # which would list the device as having unexpected administrators when the
    # check simply failed.
    Write-Error -Message $message -ErrorAction Continue
    exit $ExitError
}

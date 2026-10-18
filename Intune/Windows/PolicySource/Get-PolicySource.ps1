# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/zenpachi-alt/endpoint-engineering

#Requires -Version 5.1

<#
.SYNOPSIS
    Shows where each policy setting on this device comes from - Group Policy,
    Intune, both or neither - and which one is in effect.

.DESCRIPTION
    Read-only. Run on the device, elevated, by an administrator tracing a
    setting, or by two teams settling who owns one.

    In a hybrid estate one registry value can be written by a GPO and by an
    Intune policy. Intune writes many settings to the same Policies keys Group
    Policy uses, so a message such as "a Group Policy setting prevents this"
    names the mechanism, not the team. This script reads every local source and
    puts them side by side, one row per registry value:

        Intune (MDM)   PolicyManager: what each enrollment set, which one won,
                       and the registry value each setting maps to.
        Group Policy   The RSoP data Windows logs at every refresh: the applied
                       registry settings, the winning GPO, and the GPOs that
                       lost on precedence.
        GPO cache      Windows' local copy of each applied GPO. A setting a GPO
                       holds that RSoP does not show was not applied.
        Preferences    The local history of Group Policy Preferences registry
                       items.
        ADMX           The administrative templates in %windir%\PolicyDefinitions
                       and the copies Windows keeps of ADMX files an MDM
                       ingested: what each policy writes to the registry, and
                       its name in Group Policy.
        Registry       The value Windows reads now.

    Nothing contacts a domain controller or the internet, so the script works
    off the corporate network. gpresult is not used: it needs a domain
    controller and stalls without one.

    Verdicts, most important first:
        Conflict         Group Policy and Intune both apply it, with different
                         values.
        OverriddenByMdm  A GPO sets it, but it was not applied because Intune
                         sets it too (ControlPolicyConflict/MDMWinsOverGP). RSoP
                         and rsop.msc do not show these.
        NotApplied       A GPO sets it, it was not applied, and no Intune
                         setting explains why.
        Both             Both set it. Intune sends an ADMX state (Enabled,
                         Disabled) rather than a value, and its ADMX definition
                         was not found, so the GPO's value is compared with the
                         one in the registry instead.
        Agree            Both set it, to the same value.
        GpOnly           Group Policy only.
        MdmOnly          Intune, or another MDM, only.
        Leftover         PolicyManager still lists an MDM setting for it, but
                         no enrollment holds a value, so no MDM applies it now:
                         what remains when a policy is removed from the device,
                         or, briefly, while an MDM re-applies its policies. Run
                         again after a sync to tell which. Any registry value
                         it wrote may have stayed behind.
        Unclaimed        A value under HKLM\SOFTWARE\Policies that none of the
                         sources claims: a script, an app, another management
                         tool, or a Windows default.

    An ADMX-backed MDM setting sends a state, such as Enabled with data, not
    the value the registry holds. Its ADMX definition says which registry
    values that state writes, and what each one is: MdmRegistryValue. Those
    values are compared with Group Policy's and the registry's like any other.

    A value is matched to an MDM setting by the value itself, through the
    setting's ADMX definition, or only by its key, when the setting's ADMX
    definition was not found. MatchedBy says which (Value, Admx, Key); a match
    by key is weaker evidence. A value under the key of an ADMX setting whose
    definition does not write it is not credited to that setting.

    Settings Windows provisions for itself through PolicyManager - power and
    processor tuning, mostly, hundreds of them - are left out unless
    -IncludeWindowsInternal is given.

.PARAMETER Filter
    Only settings matching one of these wildcard patterns, tried against the
    setting name, the registry path, the Intune setting, the GPO name, the ADMX
    policy and its name in Group Policy.

.PARAMETER Verdict
    Only settings with one of these verdicts.

.PARAMETER IncludeWindowsInternal
    Include the settings Windows provisions for itself through PolicyManager.

.PARAMETER LogDirectory
    Directory for the script log. Defaults to
    %ProgramData%\EndpointEngineering\Logs. The log holds counts and timings,
    not values.

.PARAMETER MaxLogSizeBytes
    Size at which the log is rotated to a single .old copy.

.EXAMPLE
    .\Get-PolicySource.ps1 -Filter '*FVE*', '*BitLocker*'

    BitLocker settings, wherever they come from. FVE is BitLocker's policy key.

.EXAMPLE
    .\Get-PolicySource.ps1 -Verdict Conflict, OverriddenByMdm, NotApplied

    Only the settings both sides claim, where one of them loses.

.EXAMPLE
    .\Get-PolicySource.ps1 -Filter '*WindowsUpdate*' | Format-List

    Every property of each Windows Update setting, including the note that
    explains the verdict.

.EXAMPLE
    .\Get-PolicySource.ps1 -Filter '*Terminal Services*' |
        Format-Table -Property Verdict, PolicyDisplayName, GpValue, MdmRegistryValue, LiveValue -Wrap

    Remote Desktop settings by their Group Policy names, with the value Group
    Policy sets, the value Intune's ADMX state means, and the one in effect.

.EXAMPLE
    .\Get-PolicySource.ps1 | Export-Csv -Path .\PolicySource.csv -NoTypeInformation

    Everything, as a file for the other team. It holds GPO names and policy
    values from this device; scrub it before it leaves the organisation.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.2.0
    Last updated  : 2026-10-18

    PowerShell    : Windows PowerShell 5.1. It runs on the device, where
                    PowerShell 7 cannot be assumed.
    Kind          : Run by a person on the device, not delivered by Intune, so
                    the remediation exit code contract does not apply.
    Context       : Elevated. RSoP data and the GPO cache are readable by
                    administrators only; the script checks and says so.
    Modules       : None.
    Graph scopes  : None. Nothing leaves the device.
    Admin consent : Not applicable.
    Licensing     : None to run. It reads what Group Policy and an MDM
                    (Microsoft Intune Plan 1 or another) have applied.
    Role required : Local administrator on the device.

    Exit codes    : 0 success, including when no setting matches.
                    1 not elevated, or Intune or Group Policy data could not
                      be read. The reason is on stderr and in the log.

    Limits        : Computer settings only, not user settings. Registry-based
                    policy only: security settings (passwords, user rights,
                    audit) go through a separate engine and are not read.
                    ADMX states are translated with the ADMX files on the
                    device, not the central store, which needs a domain
                    controller. An ADMX setting whose definition is not found
                    is compared and matched by key as before, and a value
                    matched by key names every such setting that writes under
                    the key. A setting written by a script or an app is
                    Unclaimed only under HKLM\SOFTWARE\Policies.

.LINK
    https://learn.microsoft.com/windows/client-management/mdm/policy-csp-controlpolicyconflict
#>

[CmdletBinding()]
[OutputType([pscustomobject])]
param (
    [Parameter(Position = 0)]
    [ValidateNotNullOrEmpty()]
    [SupportsWildcards()]
    [string[]]$Filter,

    [Parameter()]
    [ValidateSet('Conflict', 'OverriddenByMdm', 'NotApplied', 'Both', 'Agree', 'GpOnly', 'MdmOnly', 'Leftover', 'Unclaimed')]
    [string[]]$Verdict,

    [Parameter()]
    [switch]$IncludeWindowsInternal,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$LogDirectory = (Join-Path -Path $env:ProgramData -ChildPath 'EndpointEngineering\Logs'),

    [Parameter()]
    [ValidateRange(65536, 104857600)]
    [int]$MaxLogSizeBytes = 1048576
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExitSuccess = 0
$ExitFailure = 1

$PolicyManagerPath = 'SOFTWARE\Microsoft\PolicyManager'
$PoliciesPath = 'SOFTWARE\Policies'
$GpoCacheDirectory = Join-Path -Path $env:windir -ChildPath 'System32\GroupPolicy\DataStore'
$PreferencesHistoryDirectory = Join-Path -Path $env:ProgramData -ChildPath 'Microsoft\Group Policy\History'
$PolicyDefinitionsDirectory = Join-Path -Path $env:windir -ChildPath 'PolicyDefinitions'

# Verdicts in the order they are listed: the ones that need a decision first.
$VerdictRank = @{
    Conflict = 0; OverriddenByMdm = 1; NotApplied = 2; Both = 3; Agree = 4; GpOnly = 5; MdmOnly = 6; Leftover = 7; Unclaimed = 8
}

# Set by Initialize-LogFile. $null means "log to the verbose stream only".
$script:LogFile = $null

function Initialize-LogFile {
    <#
        .SYNOPSIS
            Creates the log directory, rotates an oversized log, and returns the
            log file path. Returns $null when logging is not possible, so that a
            logging problem never fails a run.
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
            Never writes to the pipeline, which carries the results.
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

function Test-Elevated {
    <#
        .SYNOPSIS
            True when the current process runs as an administrator.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param ()

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList $identity

    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RegistryValueSet {
    <#
        .SYNOPSIS
            Every value of one key below Root, as a hashtable, or $null when the
            key does not exist.

        .DESCRIPTION
            Registry reads go through .NET, not the registry provider. In
            Windows PowerShell 5.1 the provider takes about 100 ms per
            Test-Path or Get-ItemProperty on a PolicyManager key, which over
            hundreds of policies stalls for minutes. .NET also reads a '/' in a
            policy name as part of the key name, where the provider would take
            it as a path separator.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryKey]$Root,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $key = $Root.OpenSubKey($Path)
    if ($null -eq $key) { return $null }

    try {
        $values = @{}
        foreach ($name in $key.GetValueNames()) {
            if ($name) {
                $values[$name] = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            }
        }
        return $values
    }
    finally {
        $key.Dispose()
    }
}

function Get-RegistrySubKeyName {
    <#
        .SYNOPSIS
            Subkey names of one key below Root, or $null when the key does not exist.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param (
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryKey]$Root,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $key = $Root.OpenSubKey($Path)
    if ($null -eq $key) { return $null }

    try {
        return , $key.GetSubKeyNames()
    }
    finally {
        $key.Dispose()
    }
}

function Get-KeyPath {
    <#
        .SYNOPSIS
            A registry key path without a hive prefix or surrounding backslashes,
            the form PolicyManager, RSoP and Registry.pol files are compared in.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Key
    )

    return ($Key.Trim('\') -replace '^(HKEY_LOCAL_MACHINE|HKLM:?|MACHINE)\\', '').TrimEnd('\')
}

function Get-LocationId {
    <#
        .SYNOPSIS
            The case-insensitive identity of one registry value.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Key,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ValueName
    )

    return ('{0}|{1}' -f (Get-KeyPath -Key $Key), $ValueName).ToLowerInvariant()
}

function ConvertTo-ValueText {
    <#
        .SYNOPSIS
            A registry value as comparable text: DWORDs and QWORDs unsigned,
            multi-strings joined with '; ', binary data as base64.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [AllowEmptyCollection()]
        $Value
    )

    if ($null -eq $Value) { return $null }
    if ($Value -is [byte[]]) { return [Convert]::ToBase64String($Value) }
    if ($Value -is [int]) { return [string][BitConverter]::ToUInt32([BitConverter]::GetBytes($Value), 0) }
    if ($Value -is [long]) { return [string][BitConverter]::ToUInt64([BitConverter]::GetBytes($Value), 0) }
    if ($Value -is [array]) { return (@($Value) -join '; ') }
    return [string]$Value
}

function ConvertFrom-PolicyValue {
    <#
        .SYNOPSIS
            Policy data stored as raw bytes and a registry type - in RSoP and in
            Registry.pol files - as the same text ConvertTo-ValueText gives for
            the value in the registry.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [byte[]]$Data,

        [Parameter(Mandatory)]
        [uint32]$Type
    )

    if ($null -eq $Data) { return $null }

    switch ($Type) {
        { $_ -in 1, 2 } {
            return [Text.Encoding]::Unicode.GetString($Data).TrimEnd([char]0)
        }
        7 {
            $parts = [Text.Encoding]::Unicode.GetString($Data).Split([char]0) | Where-Object { $_ -ne '' }
            return (@($parts) -join '; ')
        }
        4 {
            if ($Data.Length -ge 4) { return [string][BitConverter]::ToUInt32($Data, 0) }
        }
        5 {
            if ($Data.Length -ge 4) {
                $copy = $Data[0..3]
                [Array]::Reverse($copy)
                return [string][BitConverter]::ToUInt32([byte[]]$copy, 0)
            }
        }
        11 {
            if ($Data.Length -ge 8) { return [string][BitConverter]::ToUInt64($Data, 0) }
        }
    }

    if ($Data.Length -eq 0) { return '' }
    return [Convert]::ToBase64String($Data)
}

function Get-LiveValue {
    <#
        .SYNOPSIS
            The value Windows reads now, as text, or $null when it is not set.
            A key the caller may not read gives '(not readable)' rather than
            failing the run.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryKey]$Root,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Key,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Name
    )

    try {
        $handle = $Root.OpenSubKey((Get-KeyPath -Key $Key))
    }
    catch [System.Security.SecurityException] {
        return '(not readable)'
    }
    if ($null -eq $handle) { return $null }

    try {
        return ConvertTo-ValueText -Value $handle.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    }
    finally {
        $handle.Dispose()
    }
}

function Test-AdmxState {
    <#
        .SYNOPSIS
            True when an MDM value is an ADMX state (<enabled/> or <disabled/>)
            rather than a value the registry would hold.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value
    )

    return [bool]($Value -match '^\s*<(enabled|disabled)\s*/>')
}

function Format-MdmValue {
    <#
        .SYNOPSIS
            An MDM value for display. An ADMX state becomes Enabled or Disabled,
            with any data elements as id=value pairs.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value
    )

    if ($Value -match '^\s*<disabled\s*/>') { return 'Disabled' }
    if ($Value -notmatch '^\s*<enabled\s*/>') { return $Value }

    $pairs = foreach ($match in [regex]::Matches($Value, '<data\s+id="([^"]*)"\s+value="([^"]*)"\s*/>')) {
        '{0}={1}' -f $match.Groups[1].Value, $match.Groups[2].Value
    }
    if (@($pairs).Count -eq 0) { return 'Enabled' }
    return 'Enabled: ' + (@($pairs) -join '; ')
}

function Get-EnrollmentSource {
    <#
        .SYNOPSIS
            For each enrollment ID, who it stands for: Intune, another MDM, or
            Windows itself.

        .DESCRIPTION
            PolicyManager records the winning enrollment of each setting. The
            Intune enrollment has ProviderID 'MS DM Server'. Enrollments of type 1
            without a ProviderID are Windows' own: they provision power and
            processor tuning and a few security defaults.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryKey]$Root
    )

    $sources = @{}
    $ids = Get-RegistrySubKeyName -Root $Root -Path 'SOFTWARE\Microsoft\Enrollments'
    if ($null -eq $ids) { return $sources }

    foreach ($id in $ids) {
        $values = Get-RegistryValueSet -Root $Root -Path "SOFTWARE\Microsoft\Enrollments\$id"
        if ($null -eq $values) { continue }

        $provider = [string]$values['ProviderID']
        if ($provider -eq 'MS DM Server') {
            $sources[$id] = [pscustomobject]@{ Label = 'Intune'; Kind = 'Intune' }
        }
        elseif ($provider) {
            $sources[$id] = [pscustomobject]@{ Label = $provider; Kind = 'Other' }
        }
        elseif ($null -ne $values['EnrollmentType']) {
            if ([int]$values['EnrollmentType'] -eq 1) {
                $sources[$id] = [pscustomobject]@{ Label = 'Windows'; Kind = 'Windows' }
            }
            else {
                $sources[$id] = [pscustomobject]@{ Label = ('Windows enrollment type {0}' -f $values['EnrollmentType']); Kind = 'Other' }
            }
        }
    }

    return $sources
}

function Get-AdmxMetadataIndex {
    <#
        .SYNOPSIS
            Where PolicyManager keeps the metadata of each ingested ADMX policy:
            'area|policy' to the key path under AdmxDefault.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryKey]$Root
    )

    $index = @{}
    $base = "$PolicyManagerPath\AdmxDefault"
    $owners = Get-RegistrySubKeyName -Root $Root -Path $base
    if ($null -eq $owners) { return $index }

    foreach ($owner in $owners) {
        $areas = Get-RegistrySubKeyName -Root $Root -Path "$base\$owner"
        if ($null -eq $areas) { continue }
        foreach ($area in $areas) {
            $policies = Get-RegistrySubKeyName -Root $Root -Path "$base\$owner\$area"
            if ($null -eq $policies) { continue }
            foreach ($policy in $policies) {
                $index[('{0}|{1}' -f $area, $policy).ToLowerInvariant()] = "$base\$owner\$area\$policy"
            }
        }
    }

    return $index
}

function Get-MdmPolicy {
    <#
        .SYNOPSIS
            Every device-scope setting in PolicyManager: its value, the winning
            enrollment, and the registry value it maps to.

        .DESCRIPTION
            current\device\<Area> lists each setting. Its value is there, or -
            for a setting stored at its registry location - only in the store of
            the winning enrollment, providers\<id>\default\device\<Area>; the
            current key then holds just <Policy>_ProviderSet and
            <Policy>_WinningProvider.

            The mapping comes from the setting's metadata, in default\<Area>
            for settings built into Windows and in AdmxDefault for ingested
            ADMX: RegKeyPathRedirect and RegValueNameRedirect name the registry
            value the setting writes, and GPBlockingRegKeyPath and
            GPBlockingRegValueName the Group Policy value MDMWinsOverGP blocks.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryKey]$Root,

        [Parameter(Mandatory)]
        [hashtable]$Source
    )

    $metadataSuffix = '^(.+)_(ProviderSet|WinningProvider|LastWrite|ADMXInstanceData|Dirty)$'
    $areas = Get-RegistrySubKeyName -Root $Root -Path "$PolicyManagerPath\current\device"
    if ($null -eq $areas) { return }

    $builtIn = @{}
    $defaultAreas = Get-RegistrySubKeyName -Root $Root -Path "$PolicyManagerPath\default"
    if ($null -ne $defaultAreas) {
        foreach ($area in $defaultAreas) { $builtIn[$area] = $true }
    }
    $admxIndex = Get-AdmxMetadataIndex -Root $Root
    $unknown = [pscustomobject]@{ Label = 'Unknown'; Kind = 'Other' }
    $windows = [pscustomobject]@{ Label = 'Windows'; Kind = 'Windows' }
    $nobody = [pscustomobject]@{ Label = 'None'; Kind = 'Leftover' }

    foreach ($area in $areas) {
        $values = Get-RegistryValueSet -Root $Root -Path "$PolicyManagerPath\current\device\$area"
        if ($null -eq $values) { continue }

        $names = @{}
        foreach ($name in @($values.Keys)) {
            if ($name -match $metadataSuffix) { $names[$Matches[1]] = $true }
            else { $names[$name] = $true }
        }

        $isBuiltIn = $builtIn.ContainsKey($area)
        foreach ($name in @($names.Keys)) {
            # Metadata with a suffix not listed above is skipped, not taken for a setting, and so
            # is the copy of a list setting's items PolicyManager keeps as <Policy>_<Element>_ListSet.
            $cut = $name.LastIndexOf('_')
            if ($cut -gt 0 -and $names.ContainsKey($name.Substring(0, $cut))) { continue }
            if ($name -like '*_ListSet') { continue }

            $lookup = ('{0}|{1}' -f $area, $name).ToLowerInvariant()
            $metadata = $null
            if ($isBuiltIn) {
                $metadata = Get-RegistryValueSet -Root $Root -Path "$PolicyManagerPath\default\$area\$name"
            }
            elseif ($admxIndex.ContainsKey($lookup)) {
                $metadata = Get-RegistryValueSet -Root $Root -Path $admxIndex[$lookup]
            }
            if ($null -eq $metadata) { $metadata = @{} }

            $winner = [string]$values["${name}_WinningProvider"]
            $value = $null
            if ($values.ContainsKey($name)) {
                $value = ConvertTo-ValueText -Value $values[$name]
            }
            elseif ($winner) {
                $stored = Get-RegistryValueSet -Root $Root -Path "$PolicyManagerPath\providers\$winner\default\device\$area"
                if ($null -ne $stored -and $stored.ContainsKey($name)) {
                    $value = ConvertTo-ValueText -Value $stored[$name]
                }
            }

            # knobs is Windows' own tuning whatever its record says. A setting with neither a
            # winning enrollment nor a value is one no MDM applies any more: a leftover.
            $owner = $unknown
            $leftover = $false
            if ($area -eq 'knobs') { $owner = $windows }
            elseif ($winner -and $Source.ContainsKey($winner)) { $owner = $Source[$winner] }
            elseif (-not $winner -and $null -eq $value) {
                $owner = $nobody
                $leftover = $true
            }

            [pscustomobject]@{
                Name          = "$area/$name"
                Value         = $value
                Source        = $owner.Label
                SourceKind    = $owner.Kind
                Leftover      = $leftover
                AdmxBacked    = (-not $isBuiltIn) -or ($area -like 'ADMX_*') -or $metadata.ContainsKey('AdmxMetadataDevice') -or
                    $metadata.ContainsKey('AdmxMetadataBoth') -or $metadata.ContainsKey('AdmxMetadataUser')
                RedirectKey   = [string]$metadata['RegKeyPathRedirect']
                RedirectValue = [string]$metadata['RegValueNameRedirect']
                BlockKey      = [string]$metadata['GPBlockingRegKeyPath']
                BlockValue    = [string]$metadata['GPBlockingRegValueName']
            }
        }
    }
}

function ConvertFrom-AdmxValue {
    <#
        .SYNOPSIS
            The registry data one ADMX value element holds - <decimal>,
            <longDecimal>, <string> or <delete> inside enabledValue, trueValue,
            an item's <value> and the like - as the text ConvertTo-ValueText
            gives for the value in the registry. $null when there is none.

            A negative number is shown unsigned, as the registry reader shows
            it; a number that does not parse is kept as written, so one odd
            value cannot cost a whole file.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [System.Xml.XmlNode]$Node
    )

    foreach ($child in $Node.ChildNodes) {
        if ($child -isnot [System.Xml.XmlElement]) { continue }
        $kind = $child.LocalName
        if ($kind -eq 'delete') { return [pscustomobject]@{ Text = $null; Absent = $true; Loose = $false } }
        if ($kind -eq 'decimal' -or $kind -eq 'longDecimal') {
            $text = $child.GetAttribute('value')
            $long = [long]0
            if ([long]::TryParse($text, [Globalization.NumberStyles]::Integer, [cultureinfo]::InvariantCulture, [ref]$long)) {
                $text = if ($kind -eq 'decimal') { [string][BitConverter]::ToUInt32([BitConverter]::GetBytes($long), 0) }
                else { [string][BitConverter]::ToUInt64([BitConverter]::GetBytes($long), 0) }
            }
        }
        elseif ($kind -eq 'string') { $text = $child.InnerText }
        else { continue }
        return [pscustomobject]@{ Text = $text; Absent = $false; Loose = $false }
    }
}

function ConvertFrom-AdmxList {
    <#
        .SYNOPSIS
            The items of an ADMX enabledList, disabledList, trueList, falseList or
            valueList: the registry values the list writes, each with its data.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [System.Xml.XmlElement]$Node,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Key
    )

    $listKey = $Node.GetAttribute('defaultKey')
    if (-not $listKey) { $listKey = $Key }
    foreach ($item in $Node.ChildNodes) {
        if ($item -isnot [System.Xml.XmlElement] -or $item.LocalName -ne 'item') { continue }
        $itemKey = $item.GetAttribute('key')
        if (-not $itemKey) { $itemKey = $listKey }
        $data = $null
        foreach ($value in $item.ChildNodes) {
            if ($value -is [System.Xml.XmlElement] -and $value.LocalName -eq 'value') { $data = ConvertFrom-AdmxValue -Node $value }
        }
        if ($null -eq $data) { continue }
        [pscustomobject]@{ Key = $itemKey; ValueName = $item.GetAttribute('valueName'); Value = $data }
    }
}

function Read-AdmxDocument {
    <#
        .SYNOPSIS
            The computer policies one ADMX document defines, with what each one
            writes to the registry, and its categories.

        .DESCRIPTION
            User policies are left out: only computer settings are compared.
            Each policy gets a footprint - every registry value it can write, in
            any state - and the keys its list elements fill, so a value in the
            registry can be traced to the one policy that writes it.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [System.Xml.XmlDocument]$Document,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Source,

        [Parameter()]
        [AllowNull()]
        [hashtable]$String
    )

    $root = $Document.DocumentElement
    if ($null -eq $root -or $root.LocalName -ne 'policyDefinitions') { throw 'it is not an ADMX file: the root element is not policyDefinitions' }

    $prefix = $null
    $categories = @{}
    $policies = [System.Collections.Generic.List[object]]::new()
    foreach ($section in $root.ChildNodes) {
        if ($section -isnot [System.Xml.XmlElement]) { continue }

        if ($section.LocalName -eq 'policyNamespaces') {
            foreach ($target in $section.ChildNodes) {
                if ($target -is [System.Xml.XmlElement] -and $target.LocalName -eq 'target') { $prefix = $target.GetAttribute('prefix') }
            }
        }
        elseif ($section.LocalName -eq 'categories') {
            foreach ($category in $section.ChildNodes) {
                if ($category -isnot [System.Xml.XmlElement] -or $category.LocalName -ne 'category') { continue }
                $parent = $null
                foreach ($link in $category.ChildNodes) {
                    if ($link -is [System.Xml.XmlElement] -and $link.LocalName -eq 'parentCategory') { $parent = ($link.GetAttribute('ref') -split ':')[-1] }
                }
                $categories[$category.GetAttribute('name')] = $parent
            }
        }
        elseif ($section.LocalName -eq 'policies') {
            foreach ($node in $section.ChildNodes) {
                if ($node -isnot [System.Xml.XmlElement] -or $node.LocalName -ne 'policy' -or $node.GetAttribute('class') -eq 'User') { continue }

                $name = $node.GetAttribute('name')
                $key = $node.GetAttribute('key')
                $valueName = $node.GetAttribute('valueName')
                $footprint = [System.Collections.Generic.List[object]]::new()
                $listKeys = [System.Collections.Generic.List[string]]::new()
                if ($valueName) { $footprint.Add([pscustomobject]@{ Key = $key; ValueName = $valueName }) }

                # Keys are set with brackets: an ordered dictionary has properties of its own,
                # such as Item and Count, that a dotted name would reach instead.
                $policy = [ordered]@{
                    Source = $Source; Name = $name; Key = $key; ValueName = $valueName; Category = $null
                    EnabledValue = $null; DisabledValue = $null; EnabledList = @(); DisabledList = @()
                    Elements = [System.Collections.Generic.List[object]]::new()
                }
                foreach ($part in $node.ChildNodes) {
                    if ($part -isnot [System.Xml.XmlElement]) { continue }
                    switch ($part.LocalName) {
                        'parentCategory' { $policy['Category'] = ($part.GetAttribute('ref') -split ':')[-1] }
                        'enabledValue' { $policy['EnabledValue'] = ConvertFrom-AdmxValue -Node $part }
                        'disabledValue' { $policy['DisabledValue'] = ConvertFrom-AdmxValue -Node $part }
                        'enabledList' { $policy['EnabledList'] = @(ConvertFrom-AdmxList -Node $part -Key $key) }
                        'disabledList' { $policy['DisabledList'] = @(ConvertFrom-AdmxList -Node $part -Key $key) }
                        'elements' {
                            foreach ($element in $part.ChildNodes) {
                                if ($element -isnot [System.Xml.XmlElement]) { continue }
                                $elementKey = $element.GetAttribute('key')
                                if (-not $elementKey) { $elementKey = $key }
                                $entry = [ordered]@{
                                    Type = $element.LocalName; Id = $element.GetAttribute('id'); Key = $elementKey
                                    ValueName = $element.GetAttribute('valueName')
                                    TrueValue = $null; FalseValue = $null; TrueList = @(); FalseList = @(); Choice = @()
                                }
                                foreach ($child in $element.ChildNodes) {
                                    if ($child -isnot [System.Xml.XmlElement]) { continue }
                                    switch ($child.LocalName) {
                                        'trueValue' { $entry['TrueValue'] = ConvertFrom-AdmxValue -Node $child }
                                        'falseValue' { $entry['FalseValue'] = ConvertFrom-AdmxValue -Node $child }
                                        'trueList' { $entry['TrueList'] = @(ConvertFrom-AdmxList -Node $child -Key $elementKey) }
                                        'falseList' { $entry['FalseList'] = @(ConvertFrom-AdmxList -Node $child -Key $elementKey) }
                                        'item' {
                                            $data = $null
                                            $extra = @()
                                            foreach ($inner in $child.ChildNodes) {
                                                if ($inner -isnot [System.Xml.XmlElement]) { continue }
                                                if ($inner.LocalName -eq 'value') { $data = ConvertFrom-AdmxValue -Node $inner }
                                                elseif ($inner.LocalName -eq 'valueList') { $extra = @(ConvertFrom-AdmxList -Node $inner -Key $elementKey) }
                                            }
                                            $entry['Choice'] += , [pscustomobject]@{ Value = $data; ValueList = $extra }
                                            foreach ($write in $extra) { $footprint.Add($write) }
                                        }
                                    }
                                }
                                if ($entry['Type'] -eq 'list') { $listKeys.Add($elementKey) }
                                elseif ($entry['ValueName']) { $footprint.Add([pscustomobject]@{ Key = $elementKey; ValueName = $entry['ValueName'] }) }
                                foreach ($write in @($entry['TrueList']) + @($entry['FalseList'])) { $footprint.Add($write) }
                                $policy['Elements'].Add([pscustomobject]$entry)
                            }
                        }
                    }
                }
                foreach ($write in @($policy['EnabledList']) + @($policy['DisabledList'])) { $footprint.Add($write) }

                $displayName = $null
                if ($null -ne $String -and $node.GetAttribute('displayName') -match '^\$\(string\.(.+)\)$' -and $String.ContainsKey($Matches[1])) {
                    $displayName = $String[$Matches[1]]
                }
                $policy['Label'] = '{0}: {1}' -f $Source, $name
                $policy['DisplayName'] = $displayName
                $policy['Footprint'] = $footprint.ToArray()
                $policy['ListKeys'] = $listKeys.ToArray()
                $policy['CategoryPath'] = $null
                $policies.Add([pscustomobject]$policy)
            }
        }
    }

    return [pscustomobject]@{ Prefix = $prefix; Category = $categories; Policy = $policies.ToArray() }
}

function Read-AdmlString {
    <#
        .SYNOPSIS
            The string table of one ADML file: string id to text.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $xml = New-Object -TypeName System.Xml.XmlDocument
    $xml.Load($Path)
    $strings = @{}
    foreach ($node in $xml.SelectNodes("//*[local-name()='stringTable']/*[local-name()='string']")) {
        $strings[$node.GetAttribute('id')] = $node.InnerText
    }
    return $strings
}

function Test-AdmxText {
    <#
        .SYNOPSIS
            True when the start of a file or a registry string looks like an
            ADMX document, whatever its name and encoding.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Text
    )

    return $Text.Contains('<policyDefinitions')
}

function Get-IngestedAdmxDocument {
    <#
        .SYNOPSIS
            The copies Windows keeps of ADMX files an MDM ingested through
            ADMXInstall, from the given folders and from PolicyManager's
            AdmxInstalled key.

        .DESCRIPTION
            Microsoft documents that an ingested file is kept on disk but not
            where, so a file counts by its content, not its name or extension.
            Folders that cannot be read are logged and skipped.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$Directory = @(),

        [Parameter()]
        [AllowNull()]
        [Microsoft.Win32.RegistryKey]$Root,

        [Parameter()]
        [ValidateRange(1, 100000)]
        [int]$MaxFiles = 5000
    )

    $seen = 0
    foreach ($start in $Directory) {
        if (-not [IO.Directory]::Exists($start)) { continue }
        $pending = [System.Collections.Generic.Stack[string]]::new()
        $pending.Push($start)
        while ($pending.Count -gt 0) {
            $folder = $pending.Pop()
            try {
                foreach ($sub in [IO.Directory]::GetDirectories($folder)) { $pending.Push($sub) }
                $files = [IO.Directory]::GetFiles($folder)
            }
            catch {
                Write-LogEntry -Message "Ingested ADMX: could not list a folder under $start ($($_.Exception.GetType().Name)); it is skipped." -Level WARN
                continue
            }
            foreach ($file in $files) {
                if (++$seen -gt $MaxFiles) {
                    Write-LogEntry -Message "Ingested ADMX: stopped after $MaxFiles files under $start." -Level WARN
                    return
                }
                try {
                    $stream = [IO.File]::OpenRead($file)
                    try {
                        $head = New-Object -TypeName byte[] -ArgumentList 2048
                        $read = $stream.Read($head, 0, $head.Length)
                    }
                    finally {
                        $stream.Dispose()
                    }
                    $text = [Text.Encoding]::UTF8.GetString($head, 0, $read)
                    if (-not (Test-AdmxText -Text $text) -and -not (Test-AdmxText -Text ([Text.Encoding]::Unicode.GetString($head, 0, $read)))) { continue }
                    $xml = New-Object -TypeName System.Xml.XmlDocument
                    $xml.Load($file)
                    [pscustomobject]@{ Document = $xml; Origin = 'File' }
                }
                catch {
                    Write-LogEntry -Message "Ingested ADMX: a file under $start could not be read ($($_.Exception.GetType().Name)); it is skipped." -Level WARN
                }
            }
        }
    }

    if ($null -eq $Root) { return }
    foreach ($value in @(Get-RegistryValueLocation -Root $Root -Path "$PolicyManagerPath\AdmxInstalled" -MaxKeys 5000)) {
        try {
            $key = $Root.OpenSubKey($value.Key)
            if ($null -eq $key) { continue }
            try {
                $data = $key.GetValue($value.ValueName)
            }
            finally {
                $key.Dispose()
            }
            if ($data -isnot [string] -or -not (Test-AdmxText -Text $data)) { continue }
            $xml = New-Object -TypeName System.Xml.XmlDocument
            $xml.LoadXml($data)
            [pscustomobject]@{ Document = $xml; Origin = 'Registry' }
        }
        catch {
            Write-LogEntry -Message "Ingested ADMX: a value under AdmxInstalled could not be read ($($_.Exception.GetType().Name)); it is skipped." -Level WARN
        }
    }
}

function Import-AdmxDefinition {
    <#
        .SYNOPSIS
            Every computer policy in the ADMX files on this device, indexed by
            file, by ingested area, by the registry values each one writes, and
            by key.

        .DESCRIPTION
            Built-in files come from Directory, with display names from the ADML
            of the first of Language that has one. Ingested files come from
            Get-IngestedAdmxDocument; they carry no ADML.

            A built-in file that cannot be read is recorded under Failed with
            the reason, so each setting it defines can say why it is compared
            the way it is. The run itself does not fail over one file.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Directory,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$IngestedDirectory = @(),

        [Parameter()]
        [AllowNull()]
        [Microsoft.Win32.RegistryKey]$Root,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$Language = @('en-US')
    )

    if (-not [IO.Directory]::Exists($Directory)) { throw "there is no ADMX folder at $Directory" }

    $index = [pscustomobject]@{
        Directory    = $Directory
        Files        = @{}
        Failed       = @{}
        ByFile       = @{}
        Ingested     = @{}
        IngestedName = @{}
        ByValue      = @{}
        ByListKey    = @{}
        ByKey        = @{}
        WithoutAdml  = 0
        IngestedFrom = @{ File = 0; Registry = 0 }
    }
    $all = [System.Collections.Generic.List[object]]::new()

    foreach ($path in [IO.Directory]::GetFiles($Directory, '*.admx')) {
        $base = [IO.Path]::GetFileNameWithoutExtension($path)
        $file = [IO.Path]::GetFileName($path)
        # An ADML only names the policies, so one that cannot be read costs the names, not the file.
        $strings = $null
        foreach ($culture in $Language) {
            $adml = [IO.Path]::Combine($Directory, $culture, "$base.adml")
            if (-not [IO.File]::Exists($adml)) { continue }
            try {
                $strings = Read-AdmlString -Path $adml
            }
            catch {
                Write-LogEntry -Message "ADMX definitions: $culture\$base.adml could not be read: $($_.Exception.Message)" -Level WARN
            }
            break
        }
        try {
            $xml = New-Object -TypeName System.Xml.XmlDocument
            $xml.Load($path)
            $document = Read-AdmxDocument -Document $xml -Source $file -String $strings
        }
        catch {
            $index.Failed[$base.ToLowerInvariant()] = $_.Exception.Message
            continue
        }
        if ($null -eq $strings) { $index.WithoutAdml++ }
        $index.Files[$base.ToLowerInvariant()] = $true
        foreach ($policy in $document.Policy) {
            $index.ByFile[('{0}|{1}' -f $base, $policy.Name).ToLowerInvariant()] = $policy
            $all.Add($policy)
        }
    }

    # Ingested files are found by area: <App>~<SettingType>~<category path>. The path
    # runs from the top category down, by name, and may cross into another ingested file.
    $ingested = @(Get-IngestedAdmxDocument -Directory $IngestedDirectory -Root $Root)
    $documents = [System.Collections.Generic.List[object]]::new()
    $categories = @{}
    foreach ($copy in $ingested) {
        try {
            $label = 'ingested ADMX'
            $target = $copy.Document.SelectSingleNode("/*[local-name()='policyDefinitions']/*[local-name()='policyNamespaces']/*[local-name()='target']")
            if ($null -ne $target -and $target.GetAttribute('prefix')) { $label = 'ingested {0}' -f $target.GetAttribute('prefix') }
            $document = Read-AdmxDocument -Document $copy.Document -Source $label
        }
        catch {
            Write-LogEntry -Message "Ingested ADMX: a document could not be read: $($_.Exception.Message)" -Level WARN
            continue
        }
        $index.IngestedFrom[$copy.Origin]++
        $documents.Add($document)
        foreach ($name in @($document.Category.Keys)) {
            if (-not $categories.ContainsKey($name)) { $categories[$name] = $document.Category[$name] }
        }
    }
    foreach ($document in $documents) {
        foreach ($policy in $document.Policy) {
            $path = [System.Collections.Generic.List[string]]::new()
            $category = $policy.Category
            while ($category -and $path.Count -lt 32 -and -not $path.Contains($category)) {
                $path.Insert(0, $category)
                $category = if ($document.Category.ContainsKey($category)) { $document.Category[$category] }
                elseif ($categories.ContainsKey($category)) { $categories[$category] }
                else { $null }
            }
            $policy.CategoryPath = $path -join '~'
            $index.Ingested[('{0}|{1}' -f $policy.CategoryPath, $policy.Name).ToLowerInvariant()] = $policy
            $name = $policy.Name.ToLowerInvariant()
            if (-not $index.IngestedName.ContainsKey($name)) { $index.IngestedName[$name] = [System.Collections.Generic.List[object]]::new() }
            $index.IngestedName[$name].Add($policy)
            $all.Add($policy)
        }
    }

    # A script block rather than a function: it runs thousands of times, and an advanced
    # function call costs far more in Windows PowerShell 5.1. Keys are lowercased the way
    # Get-LocationId and Get-KeyPath give them.
    $add = {
        param ([hashtable]$Table, [string]$Name, $Policy)
        if (-not $Table.ContainsKey($Name)) { $Table[$Name] = [System.Collections.Generic.List[object]]::new() }
        if (-not $Table[$Name].Contains($Policy)) { $Table[$Name].Add($Policy) }
    }
    foreach ($policy in $all) {
        foreach ($write in $policy.Footprint) {
            $id = ('{0}|{1}' -f $write.Key.Trim('\'), $write.ValueName).ToLowerInvariant()
            & $add $index.ByValue $id $policy
        }
        foreach ($listKey in $policy.ListKeys) { & $add $index.ByListKey $listKey.Trim('\').ToLowerInvariant() $policy }
        & $add $index.ByKey $policy.Key.Trim('\').ToLowerInvariant() $policy
    }

    return $index
}

function Get-AdmxStateData {
    <#
        .SYNOPSIS
            An MDM ADMX state taken apart: enabled or disabled, and the value of
            each <data> element by its id, lowercased. $null when the value is
            not an ADMX state or is not well-formed.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value
    )

    if (-not (Test-AdmxState -Value $Value)) { return $null }

    # Wrapped in one element, the state reads as XML, which also decodes &#xF000; and &amp;.
    $xml = New-Object -TypeName System.Xml.XmlDocument
    try {
        $xml.LoadXml("<state>$Value</state>")
    }
    catch {
        return $null
    }

    $state = $null
    $data = @{}
    foreach ($node in $xml.DocumentElement.ChildNodes) {
        if ($node -isnot [System.Xml.XmlElement]) { continue }
        $kind = $node.LocalName.ToLowerInvariant()
        if ($kind -eq 'enabled' -or $kind -eq 'disabled') {
            if (-not $state) { $state = $kind }
        }
        elseif ($kind -eq 'data') {
            # Attribute names are matched in any case: Microsoft's own examples use both.
            $id = $null; $text = ''
            foreach ($attribute in $node.Attributes) {
                if ($attribute.LocalName -eq 'id') { $id = $attribute.Value }
                elseif ($attribute.LocalName -eq 'value') { $text = $attribute.Value }
            }
            if ($id) { $data[$id.ToLowerInvariant()] = $text }
        }
    }
    if (-not $state) { return $null }

    return [pscustomobject]@{ State = $state; Data = $data }
}

function ConvertFrom-AdmxState {
    <#
        .SYNOPSIS
            The registry values an MDM ADMX state stands for, worked out from
            the ADMX definition of its policy.

        .DESCRIPTION
            Enabled writes the policy's enabledValue - 1 where the ADMX gives
            none - and its enabledList, then each element from its data: a
            decimal as the number, a boolean as its trueValue or falseValue, an
            enum as the item whose value the data names with that item's
            valueList, text as it is, multiText split on U+F000, and a list as
            name/value pairs split on U+F000. Disabled removes the element
            values, then writes disabledValue and the disabledList.

            Where the ADMX gives no disabledValue or falseValue, Windows may
            write 0 or remove the value, so either counts as the state's value
            (Loose). An element the state gives no data for, or data the
            definition does not offer, is left out rather than guessed.

            Returns Value - location id to the expected value - and ListKey, the
            keys of the list elements the state fills or empties, or $null when
            the value is not an ADMX state.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [pscustomobject]$Definition,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value
    )

    $parsed = Get-AdmxStateData -Value $Value
    if ($null -eq $parsed) { return $null }

    $one = [pscustomobject]@{ Text = '1'; Absent = $false; Loose = $false }
    $zero = [pscustomobject]@{ Text = '0'; Absent = $false; Loose = $true }
    $gone = [pscustomobject]@{ Text = $null; Absent = $true; Loose = $false }
    $writes = @{}
    $listKeys = [System.Collections.Generic.List[string]]::new()
    $set = {
        param ([string]$Key, [string]$Name, $Data)
        $writes[('{0}|{1}' -f $Key.Trim('\'), $Name).ToLowerInvariant()] = [pscustomobject]@{
            Key = $Key; ValueName = $Name; Text = $Data.Text; Absent = $Data.Absent; Loose = $Data.Loose
        }
    }
    $text = {
        param ([string]$Data)
        [pscustomobject]@{ Text = $Data; Absent = $false; Loose = $false }
    }

    if ($parsed.State -eq 'enabled') {
        if ($Definition.ValueName) {
            & $set $Definition.Key $Definition.ValueName $(if ($null -ne $Definition.EnabledValue) { $Definition.EnabledValue } else { $one })
        }
        foreach ($write in $Definition.EnabledList) { & $set $write.Key $write.ValueName $write.Value }

        foreach ($element in $Definition.Elements) {
            $id = ([string]$element.Id).ToLowerInvariant()
            if (-not $parsed.Data.ContainsKey($id)) { continue }
            $data = [string]$parsed.Data[$id]
            switch ($element.Type) {
                'decimal' {
                    $number = [uint32]0
                    if ([uint32]::TryParse($data, [ref]$number)) { & $set $element.Key $element.ValueName (& $text ([string]$number)) }
                }
                'longDecimal' {
                    $number = [uint64]0
                    if ([uint64]::TryParse($data, [ref]$number)) { & $set $element.Key $element.ValueName (& $text ([string]$number)) }
                }
                'text' { & $set $element.Key $element.ValueName (& $text $data) }
                'multiText' {
                    $items = @($data.Split([char]0xF000) | Where-Object { $_ -ne '' })
                    & $set $element.Key $element.ValueName (& $text ($items -join '; '))
                }
                'boolean' {
                    if ($data -eq 'true' -or $data -eq '1') {
                        if ($element.ValueName) { & $set $element.Key $element.ValueName $(if ($null -ne $element.TrueValue) { $element.TrueValue } else { $one }) }
                        foreach ($write in $element.TrueList) { & $set $write.Key $write.ValueName $write.Value }
                    }
                    elseif ($data -eq 'false' -or $data -eq '0') {
                        if ($element.ValueName) { & $set $element.Key $element.ValueName $(if ($null -ne $element.FalseValue) { $element.FalseValue } else { $zero }) }
                        foreach ($write in $element.FalseList) { & $set $write.Key $write.ValueName $write.Value }
                    }
                }
                'enum' {
                    foreach ($choice in $element.Choice) {
                        if ($null -eq $choice.Value -or $choice.Value.Text -ne $data) { continue }
                        if ($element.ValueName) { & $set $element.Key $element.ValueName $choice.Value }
                        foreach ($write in $choice.ValueList) { & $set $write.Key $write.ValueName $write.Value }
                        break
                    }
                }
                'list' {
                    $parts = $data.Split([char]0xF000)
                    if ($data -and $parts.Count % 2 -eq 0) {
                        for ($at = 0; $at -lt $parts.Count; $at += 2) {
                            if ($parts[$at]) { & $set $element.Key $parts[$at] (& $text $parts[$at + 1]) }
                        }
                        $listKeys.Add($element.Key)
                    }
                }
            }
        }
    }
    else {
        foreach ($element in $Definition.Elements) {
            if ($element.Type -eq 'list') { $listKeys.Add($element.Key) }
            elseif ($element.ValueName) { & $set $element.Key $element.ValueName $gone }
        }
        if ($Definition.ValueName) {
            & $set $Definition.Key $Definition.ValueName $(if ($null -ne $Definition.DisabledValue) { $Definition.DisabledValue } else { $zero })
        }
        foreach ($write in $Definition.DisabledList) { & $set $write.Key $write.ValueName $write.Value }
    }

    return [pscustomobject]@{ Value = $writes; ListKey = $listKeys.ToArray() }
}

function Test-ExpectedValue {
    <#
        .SYNOPSIS
            True when Value - registry text, or $null for no value - is what an
            MDM ADMX state means at that registry value.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [pscustomobject]$Expected,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        $Value
    )

    if ($Expected.Absent) { return ($null -eq $Value) }
    if ($Expected.Loose -and $null -eq $Value) { return $true }
    return ($null -ne $Value -and [string]$Value -eq $Expected.Text)
}

function Format-ExpectedValue {
    <#
        .SYNOPSIS
            The value an MDM ADMX state means at one registry value, for display.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [pscustomobject]$Expected
    )

    if ($Expected.Absent) { return 'not set' }
    if ($Expected.Loose) { return ('{0} or not set' -f $Expected.Text) }
    return $Expected.Text
}

function Resolve-AdmxPolicy {
    <#
        .SYNOPSIS
            The ADMX policy behind one ADMX-backed MDM setting, how it was
            found, or why it was not.

        .DESCRIPTION
            In order: an ADMX_<File> area names its file; an ingested area,
            <App>~<SettingType>~<category path>, names the category path; and
            any setting can be found by the registry value PolicyManager maps it
            to. A setting PolicyManager maps to a key only is found by that key
            only when the element ids in its data pick out one policy. Only a
            single match counts: there is no guessing between two.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [pscustomobject]$Policy,

        [Parameter(Mandatory)]
        [pscustomobject]$Index
    )

    $cut = $Policy.Name.IndexOf('/')
    $area = if ($cut -gt 0) { $Policy.Name.Substring(0, $cut) } else { '' }
    $name = $Policy.Name.Substring($cut + 1)
    $kind = 'NoMatch'
    $reason = $null

    if ($area -like 'ADMX_*') {
        $file = $area.Substring(5)
        $lookup = ('{0}|{1}' -f $file, $name).ToLowerInvariant()
        if ($Index.ByFile.ContainsKey($lookup)) { return [pscustomobject]@{ Definition = $Index.ByFile[$lookup]; Kind = 'File'; Reason = $null } }
        $fileKey = $file.ToLowerInvariant()
        if ($Index.Failed.ContainsKey($fileKey)) {
            $kind = 'Unreadable'
            $reason = '{0}.admx could not be read: {1}' -f $file, $Index.Failed[$fileKey].TrimEnd('.')
        }
        elseif ($Index.Files.ContainsKey($fileKey)) {
            $kind = 'NoPolicy'
            $reason = '{0}.admx has no policy {1}' -f $file, $name
        }
        else {
            $kind = 'NoFile'
            $reason = '{0}.admx is not in {1}' -f $file, $Index.Directory
        }
    }
    elseif ($area -match '^[^~]+~[^~]+~(.+)$') {
        $lookup = ('{0}|{1}' -f $Matches[1], $name).ToLowerInvariant()
        if ($Index.Ingested.ContainsKey($lookup)) { return [pscustomobject]@{ Definition = $Index.Ingested[$lookup]; Kind = 'Ingested'; Reason = $null } }
        $named = @()
        if ($Index.IngestedName.ContainsKey($name.ToLowerInvariant())) { $named = @($Index.IngestedName[$name.ToLowerInvariant()]) }
        if (@($named | Select-Object -ExpandProperty Label -Unique).Count -eq 1) {
            return [pscustomobject]@{ Definition = $named[0]; Kind = 'Ingested'; Reason = $null }
        }
        $kind = 'NoIngested'
        $reason = if ($Index.Ingested.Count -eq 0) { 'no copy of the ingested ADMX files was found on this device' }
        else { 'none of the ingested ADMX files found defines it' }
    }

    $ids = @()
    if ($Policy.Value) { $ids = @(foreach ($match in [regex]::Matches($Policy.Value, '<data\s+id="([^"]*)"', 'IgnoreCase')) { $match.Groups[1].Value }) }
    $offering = {
        param ($Candidate)
        $offered = @($Candidate.Elements | ForEach-Object { $_.Id })
        @($ids | Where-Object { $offered -notcontains $_ }).Count -eq 0
    }
    $candidates = @()
    if ($Policy.RedirectKey -and $Policy.RedirectValue) {
        $lookup = Get-LocationId -Key $Policy.RedirectKey -ValueName $Policy.RedirectValue
        if ($Index.ByValue.ContainsKey($lookup)) { $candidates = @($Index.ByValue[$lookup]) }
        if ($candidates.Count -gt 1) {
            $own = @($candidates | Where-Object { (Get-LocationId -Key $_.Key -ValueName $_.ValueName) -eq $lookup })
            if ($own.Count -gt 0) { $candidates = $own }
        }
        if ($candidates.Count -gt 1 -and $ids.Count -gt 0) { $candidates = @($candidates | Where-Object { & $offering $_ }) }
    }
    elseif ($Policy.RedirectKey) {
        # A key alone is weak evidence: other policies write under it, and the one that does
        # may be in a file this device does not have. Only the element ids in the setting's
        # own data can pick its policy out.
        $lookup = (Get-KeyPath -Key $Policy.RedirectKey).ToLowerInvariant()
        if ($ids.Count -gt 0 -and $Index.ByKey.ContainsKey($lookup)) { $candidates = @($Index.ByKey[$lookup] | Where-Object { & $offering $_ }) }
        elseif (-not $reason) {
            $kind = 'KeyOnly'
            $reason = 'PolicyManager names only its key, and its value names no ADMX element to find the policy by'
        }
    }
    $unique = @{}
    foreach ($candidate in $candidates) { $unique[$candidate.Label] = $candidate }
    if ($unique.Count -eq 1) {
        $how = if ($Policy.RedirectValue) { 'Value' } else { 'Key' }
        return [pscustomobject]@{ Definition = @($unique.Values)[0]; Kind = $how; Reason = $null }
    }
    if (-not $reason) {
        if ($unique.Count -gt 1) {
            $kind = 'Ambiguous'
            $reason = '{0} ADMX policies match it: {1}' -f $unique.Count, (Format-NameList -Name @($unique.Keys | Sort-Object))
        }
        else {
            $reason = 'no ADMX policy on this device matches it'
        }
    }
    return [pscustomobject]@{ Definition = $null; Kind = $kind; Reason = $reason }
}

function Find-AdmxDefinition {
    <#
        .SYNOPSIS
            The ADMX policies that write one registry value, or whose list
            element fills its key: what the value is called in Group Policy.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [pscustomobject]$Index,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Key,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ValueName
    )

    $id = Get-LocationId -Key $Key -ValueName $ValueName
    if ($Index.ByValue.ContainsKey($id)) { return $Index.ByValue[$id].ToArray() }
    $listKey = (Get-KeyPath -Key $Key).ToLowerInvariant()
    if ($Index.ByListKey.ContainsKey($listKey)) { return $Index.ByListKey[$listKey].ToArray() }
    # Nothing, not $null: the caller wraps the result in @(), and @($null) holds one item.
    return
}

function Get-CimValue {
    <#
        .SYNOPSIS
            A property of a CIM instance, or $null when the class has no such
            property, without tripping strict mode.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $Instance,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    $property = $Instance.CimInstanceProperties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-AppliedGroupPolicy {
    <#
        .SYNOPSIS
            The GPOs and the applied registry settings, from the RSoP data
            Windows logs at every Group Policy refresh.

        .DESCRIPTION
            Entries without a value name create keys, and entries starting with
            ** are instructions (delete a value, a key); neither is a setting.
            Every GPO that took part is returned, with whether it applied.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param ()

    $namespace = 'root\rsop\computer'
    $gpos = @{}
    foreach ($gpo in @(Get-CimInstance -Namespace $namespace -ClassName 'RSOP_GPO' -OperationTimeoutSec 120 -ErrorAction Stop)) {
        $id = [string](Get-CimValue -Instance $gpo -Name 'id')
        $guid = [string](Get-CimValue -Instance $gpo -Name 'guidName')
        if (-not $guid -and $id -match '\{[0-9A-Fa-f-]{36}\}') { $guid = $Matches[0] }

        $applied = $true
        foreach ($flag in @(@('enabled', $true), @('filterAllowed', $true), @('accessDenied', $false))) {
            $state = Get-CimValue -Instance $gpo -Name $flag[0]
            if ($null -ne $state -and [bool]$state -ne $flag[1]) { $applied = $false }
        }

        # A domain GPO's id is its directory path; the local GPO's is not. Only domain GPOs are cached.
        $gpos[$id] = [pscustomobject]@{
            Guid    = $guid.ToUpperInvariant()
            Name    = [string](Get-CimValue -Instance $gpo -Name 'name')
            Applied = $applied
            Domain  = $id -like 'cn=*'
        }
    }

    $entries = foreach ($setting in @(Get-CimInstance -Namespace $namespace -ClassName 'RSOP_RegistryPolicySetting' -OperationTimeoutSec 120 -ErrorAction Stop)) {
        $valueName = [string](Get-CimValue -Instance $setting -Name 'valueName')
        if (-not $valueName.Trim() -or $valueName.StartsWith('**')) { continue }

        $gpoId = [string](Get-CimValue -Instance $setting -Name 'GPOID')
        $gpoName = $gpoId
        if ($gpos.ContainsKey($gpoId)) { $gpoName = $gpos[$gpoId].Name }
        $type = Get-CimValue -Instance $setting -Name 'valueType'
        if ($null -eq $type) { $type = 0 }

        [pscustomobject]@{
            Key        = Get-KeyPath -Key ([string](Get-CimValue -Instance $setting -Name 'registryKey'))
            ValueName  = $valueName
            Value      = ConvertFrom-PolicyValue -Data (Get-CimValue -Instance $setting -Name 'value') -Type ([uint32]$type)
            Precedence = [int](Get-CimValue -Instance $setting -Name 'precedence')
            GpoName    = $gpoName
        }
    }

    return [pscustomobject]@{ Gpo = $gpos; Entry = @($entries) }
}

function Read-RegistryPolString {
    <#
        .SYNOPSIS
            One null-terminated UTF-16LE string from a Registry.pol buffer, and
            the position after its terminator.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [byte[]]$Bytes,

        [Parameter(Mandatory)]
        [int]$Start
    )

    $end = $Start
    while ($end + 1 -lt $Bytes.Length -and ($Bytes[$end] -ne 0 -or $Bytes[$end + 1] -ne 0)) { $end += 2 }
    if ($end + 1 -ge $Bytes.Length) { throw "a string starting at byte $Start has no terminator" }

    return [pscustomobject]@{
        Text = [Text.Encoding]::Unicode.GetString($Bytes, $Start, $end - $Start)
        Next = $end + 2
    }
}

function Assert-RegistryPolCharacter {
    <#
        .SYNOPSIS
            Throws unless the UTF-16LE character at Position is the expected
            delimiter.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [byte[]]$Bytes,

        [Parameter(Mandatory)]
        [int]$Position,

        [Parameter(Mandatory)]
        [char]$Character
    )

    if ($Position + 1 -ge $Bytes.Length -or $Bytes[$Position] -ne [byte]$Character -or $Bytes[$Position + 1] -ne 0) {
        throw "expected '$Character' at byte $Position"
    }
}

function ConvertFrom-RegistryPol {
    <#
        .SYNOPSIS
            The entries of a Registry.pol file: the PReg header, then
            [key;value;type;size;data] records in UTF-16LE.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Source = 'The file'
    )

    if ($Bytes.Length -lt 8 -or [BitConverter]::ToUInt32($Bytes, 0) -ne 0x67655250) {
        throw "$Source is not a registry policy file: the PReg signature is missing."
    }

    $position = 8
    try {
        while ($position -lt $Bytes.Length) {
            Assert-RegistryPolCharacter -Bytes $Bytes -Position $position -Character '['
            $key = Read-RegistryPolString -Bytes $Bytes -Start ($position + 2)
            Assert-RegistryPolCharacter -Bytes $Bytes -Position $key.Next -Character ';'
            $name = Read-RegistryPolString -Bytes $Bytes -Start ($key.Next + 2)
            $position = $name.Next
            Assert-RegistryPolCharacter -Bytes $Bytes -Position $position -Character ';'
            if ($position + 14 -gt $Bytes.Length) { throw "the record at byte $position is cut short" }
            $type = [BitConverter]::ToUInt32($Bytes, $position + 2)
            Assert-RegistryPolCharacter -Bytes $Bytes -Position ($position + 6) -Character ';'
            $size = [BitConverter]::ToUInt32($Bytes, $position + 8)
            Assert-RegistryPolCharacter -Bytes $Bytes -Position ($position + 12) -Character ';'
            $position += 14
            if ($position + $size -gt $Bytes.Length) { throw "the data at byte $position runs past the end" }
            $data = New-Object -TypeName byte[] -ArgumentList $size
            [Array]::Copy($Bytes, $position, $data, 0, $size)
            $position += $size
            Assert-RegistryPolCharacter -Bytes $Bytes -Position $position -Character ']'
            $position += 2

            [pscustomobject]@{
                Key       = Get-KeyPath -Key $key.Text
                ValueName = $name.Text
                Type      = $type
                Value     = ConvertFrom-PolicyValue -Data $data -Type $type
            }
        }
    }
    catch {
        throw "$Source is malformed: $($_.Exception.Message)."
    }
}

function Get-GpoCacheEntry {
    <#
        .SYNOPSIS
            The computer registry settings in Windows' local copy of each
            applied GPO.

        .DESCRIPTION
            Windows keeps a copy of each GPO it downloads under
            System32\GroupPolicy\DataStore. Its Machine\Registry.pol holds every
            computer registry setting the GPO makes, including those that were
            not applied: RSoP lists only what was. Copies of GPOs that no longer
            apply are skipped by GUID.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Directory,

        [Parameter(Mandatory)]
        [hashtable]$AppliedGpo
    )

    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) { return }

    foreach ($file in @(Get-ChildItem -LiteralPath $Directory -Recurse -Filter 'Registry.pol' -File -ErrorAction Stop)) {
        if ($file.Directory.Name -ne 'Machine') { continue }
        $guid = $file.Directory.Parent.Name.ToUpperInvariant()
        if (-not $AppliedGpo.ContainsKey($guid)) { continue }

        foreach ($entry in @(ConvertFrom-RegistryPol -Bytes ([IO.File]::ReadAllBytes($file.FullName)) -Source "The cached GPO $guid")) {
            if (-not $entry.ValueName.Trim() -or $entry.ValueName.StartsWith('**')) { continue }
            [pscustomobject]@{
                Key       = $entry.Key
                ValueName = $entry.ValueName
                Value     = $entry.Value
                GpoName   = $AppliedGpo[$guid]
            }
        }
    }
}

function ConvertFrom-PreferenceValue {
    <#
        .SYNOPSIS
            A Group Policy Preferences registry value as comparable text. The
            XML holds DWORDs and QWORDs as hexadecimal.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Type,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )

    if ($Type -eq 'REG_DWORD' -and $Value -match '^[0-9A-Fa-f]{1,8}$') { return [string][Convert]::ToUInt32($Value, 16) }
    if ($Type -eq 'REG_QWORD' -and $Value -match '^[0-9A-Fa-f]{1,16}$') { return [string][Convert]::ToUInt64($Value, 16) }
    return $Value
}

function Get-PreferenceRegistryItem {
    <#
        .SYNOPSIS
            Computer registry items of Group Policy Preferences, from the
            history Windows keeps for each applied GPO.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Directory,

        [Parameter(Mandatory)]
        [hashtable]$AppliedGpo
    )

    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) { return }

    foreach ($folder in @(Get-ChildItem -LiteralPath $Directory -Directory -ErrorAction Stop)) {
        $guid = $folder.Name.ToUpperInvariant()
        if (-not $AppliedGpo.ContainsKey($guid)) { continue }
        $file = Join-Path -Path $folder.FullName -ChildPath 'Machine\Preferences\Registry\Registry.xml'
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { continue }

        $xml = New-Object -TypeName System.Xml.XmlDocument
        $xml.Load($file)
        foreach ($node in $xml.SelectNodes("//*[local-name()='Properties']")) {
            # 'D' deletes the value, so it sets nothing.
            if ($node.GetAttribute('hive') -ne 'HKEY_LOCAL_MACHINE' -or $node.GetAttribute('action') -eq 'D') { continue }
            $name = $node.GetAttribute('name')
            if ($node.GetAttribute('default') -eq '1') { $name = '' }

            [pscustomobject]@{
                Key       = Get-KeyPath -Key $node.GetAttribute('key')
                ValueName = $name
                Value     = ConvertFrom-PreferenceValue -Type $node.GetAttribute('type') -Value $node.GetAttribute('value')
                GpoName   = $AppliedGpo[$guid]
            }
        }
    }
}

function Get-RegistryValueLocation {
    <#
        .SYNOPSIS
            Every value under one key below Root, as Key and ValueName pairs.
            Stops after MaxKeys keys, so a huge tree cannot stall the run.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryKey]$Root,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter()]
        [ValidateRange(1, 1000000)]
        [int]$MaxKeys = 20000
    )

    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push($Path)
    $visited = 0

    while ($pending.Count -gt 0) {
        if ($visited -ge $MaxKeys) {
            Write-Warning "Stopped reading HKLM\$Path after $MaxKeys keys; values below the rest are not checked."
            return
        }
        $current = $pending.Pop()
        try {
            $key = $Root.OpenSubKey($current)
        }
        catch [System.Security.SecurityException] {
            Write-LogEntry -Message "No read access to HKLM\$current; its values are not checked." -Level WARN
            continue
        }
        if ($null -eq $key) { continue }

        try {
            $visited++
            foreach ($name in $key.GetValueNames()) {
                [pscustomobject]@{ Key = $current; ValueName = $name }
            }
            foreach ($sub in $key.GetSubKeyNames()) { $pending.Push("$current\$sub") }
        }
        finally {
            $key.Dispose()
        }
    }
}

function Get-PolicyLocation {
    <#
        .SYNOPSIS
            The record for one registry value in Table, created when missing.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Table,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Key,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ValueName
    )

    $id = Get-LocationId -Key $Key -ValueName $ValueName
    if (-not $Table.ContainsKey($id)) {
        # Via: how each MDM setting was tied to the value. Expected: what each one's ADMX
        # state means here, where its definition says.
        $Table[$id] = [pscustomobject]@{
            Key       = Get-KeyPath -Key $Key
            ValueName = $ValueName
            Applied   = [System.Collections.Generic.List[object]]::new()
            Cached    = [System.Collections.Generic.List[object]]::new()
            Preferred = [System.Collections.Generic.List[object]]::new()
            Mdm       = [System.Collections.Generic.List[object]]::new()
            Via       = @{}
            Expected  = @{}
        }
    }
    return $Table[$id]
}

function Add-LocationPolicy {
    <#
        .SYNOPSIS
            Ties an MDM setting to one registry value, recording how: Redirect
            (PolicyManager maps the setting to it), Block (MDMWinsOverGP blocks
            Group Policy there) or Admx (the setting's ADMX definition writes it).
            The first tie is the one kept.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [pscustomobject]$Location,

        [Parameter(Mandatory)]
        [pscustomobject]$Policy,

        [Parameter(Mandatory)]
        [ValidateSet('Redirect', 'Block', 'Admx')]
        [string]$Via
    )

    if (-not $Location.Mdm.Contains($Policy)) { $Location.Mdm.Add($Policy) }
    if (-not $Location.Via.ContainsKey($Policy.Name)) { $Location.Via[$Policy.Name] = $Via }
}

function Find-KeyClaim {
    <#
        .SYNOPSIS
            The ADMX-backed MDM settings that write under Key or one of its
            parents, or nothing.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Claim,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Key
    )

    $path = (Get-KeyPath -Key $Key).ToLowerInvariant()
    while ($path) {
        if ($Claim.ContainsKey($path)) { return $Claim[$path].ToArray() }
        $cut = $path.LastIndexOf('\')
        if ($cut -lt 0) { break }
        $path = $path.Substring(0, $cut)
    }
    # Nothing, not $null: the caller wraps the result in @(), and @($null) holds one item.
    return
}

function ConvertTo-PolicySourceRow {
    <#
        .SYNOPSIS
            One result row, showing the main columns by default.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Property
    )

    $row = [pscustomobject][ordered]@{
        Verdict       = $Property['Verdict']
        Setting       = $Property['Setting']
        LiveValue     = $Property['LiveValue']
        GpValue       = $Property['GpValue']
        Gpo           = $Property['Gpo']
        OverriddenGpo = $Property['OverriddenGpo']
        GpSource      = $Property['GpSource']
        MdmSetting    = $Property['MdmSetting']
        MdmValue      = $Property['MdmValue']
        MdmSource     = $Property['MdmSource']
        MdmSourceKind = $Property['MdmSourceKind']
        MatchedBy     = $Property['MatchedBy']
        RegistryPath  = $Property['RegistryPath']
        Note          = $Property['Note']
        # Added in 1.2, after the 1.1 columns so that exports from both versions line up.
        AdmxPolicy        = $Property['AdmxPolicy']
        PolicyDisplayName = $Property['PolicyDisplayName']
        MdmRegistryValue  = $Property['MdmRegistryValue']
    }

    $columns = [string[]]@('Verdict', 'Setting', 'LiveValue', 'GpValue', 'Gpo', 'MdmValue', 'MdmSource')
    $display = New-Object -TypeName System.Management.Automation.PSPropertySet -ArgumentList 'DefaultDisplayPropertySet', $columns
    Add-Member -InputObject $row -MemberType MemberSet -Name PSStandardMembers -ErrorAction Stop `
        -Value ([System.Management.Automation.PSMemberInfo[]]@($display))
    return $row
}

function Format-NameList {
    <#
        .SYNOPSIS
            Up to three names, then how many more, so a note stays readable when
            many settings write under one key.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$Name
    )

    $unique = @($Name | Select-Object -Unique)
    if ($unique.Count -le 3) { return ($unique -join ', ') }
    return ('{0} and {1} more' -f ($unique[0..2] -join ', '), ($unique.Count - 3))
}

function Resolve-PolicySource {
    <#
        .SYNOPSIS
            Puts every source side by side, one row per setting, and gives each
            a verdict.

        .DESCRIPTION
            A row is a registry value, or an MDM setting with no single registry
            value. An MDM setting that writes one value and blocks Group Policy at
            another gets one row, the one with Group Policy in it.

            With ADMX definitions (AdmxIndex), an ADMX-backed MDM setting whose
            ADMX policy is found is tied to every registry value that policy
            writes, with the value its state means there, and compared like any
            other value. A value under its key that the policy does not write is
            not credited to it. A setting whose policy is not found is matched
            by key, as without definitions.

            A leftover - an MDM setting PolicyManager still lists, with no
            enrollment holding a value - never counts as the source of a value.
            It can explain a GPO setting that was not applied, or a value left
            behind under its key.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Mdm,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$GpApplied,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$GpCached,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Preference,

        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryKey]$Root,

        [Parameter()]
        [bool]$MdmWinsOverGp,

        [Parameter()]
        [AllowNull()]
        [object]$AdmxIndex
    )

    $leftoverNote = 'PolicyManager still lists it, but no enrollment holds a value for it, so no MDM applies it now. ' +
    'That is what remains when a policy is removed from the device, and it can also show briefly while an MDM ' +
    're-applies its policies: run again after a sync to tell which. Registry values it wrote can stay behind.'

    $locations = @{}
    foreach ($entry in $GpApplied) { (Get-PolicyLocation -Table $locations -Key $entry.Key -ValueName $entry.ValueName).Applied.Add($entry) }
    foreach ($entry in $GpCached) { (Get-PolicyLocation -Table $locations -Key $entry.Key -ValueName $entry.ValueName).Cached.Add($entry) }
    foreach ($entry in $Preference) { (Get-PolicyLocation -Table $locations -Key $entry.Key -ValueName $entry.ValueName).Preferred.Add($entry) }

    # Values nobody claims are found by reading what is there. They are read before the MDM
    # settings are placed, so that an ADMX list element can claim every value under its key.
    foreach ($value in @(Get-RegistryValueLocation -Root $Root -Path $PoliciesPath)) {
        $null = Get-PolicyLocation -Table $locations -Key $value.Key -ValueName $value.ValueName
    }

    $gpKeys = @{}
    foreach ($entry in $GpApplied) { $gpKeys[(Get-KeyPath -Key $entry.Key).ToLowerInvariant()] = $true }

    # Each MDM setting goes to the registry value it writes. The value MDMWinsOverGP
    # blocks is used too, but only where Group Policy has something there. An ADMX-backed
    # setting whose ADMX policy is found goes to every value that policy writes; one whose
    # policy is not found is matched by key, below.
    $claims = @{}
    $leftoverClaims = @{}
    $admxClaims = @{}
    $listClaims = @{}
    $definitions = @{}
    $unresolved = @{}
    $found = @{}
    $placed = @{}
    foreach ($policy in $Mdm) {
        $placed[$policy.Name] = $false
        if ($policy.RedirectKey -and $policy.RedirectValue) {
            Add-LocationPolicy -Location (Get-PolicyLocation -Table $locations -Key $policy.RedirectKey -ValueName $policy.RedirectValue) -Policy $policy -Via Redirect
            $placed[$policy.Name] = $true
        }
        if ($policy.BlockKey -and $policy.BlockValue) {
            $id = Get-LocationId -Key $policy.BlockKey -ValueName $policy.BlockValue
            if ($locations.ContainsKey($id)) {
                $location = $locations[$id]
                if (-not $location.Mdm.Contains($policy) -and
                    ($location.Applied.Count + $location.Cached.Count + $location.Preferred.Count) -gt 0) {
                    Add-LocationPolicy -Location $location -Policy $policy -Via Block
                    $placed[$policy.Name] = $true
                }
            }
        }

        $definition = $null
        if ($policy.AdmxBacked -and $null -ne $AdmxIndex) {
            $resolution = Resolve-AdmxPolicy -Policy $policy -Index $AdmxIndex
            $found[$resolution.Kind] = 1 + [int]$found[$resolution.Kind]
            $definition = $resolution.Definition
            if ($null -eq $definition) { $unresolved[$policy.Name] = $resolution.Reason }
        }

        if ($null -ne $definition) {
            $definitions[$policy.Name] = $definition
            $wanted = @{}
            $filled = @()
            if (-not $policy.Leftover) {
                $translated = ConvertFrom-AdmxState -Definition $definition -Value $policy.Value
                if ($null -ne $translated) {
                    $wanted = $translated.Value
                    $filled = @($translated.ListKey | ForEach-Object { (Get-KeyPath -Key $_).ToLowerInvariant() })
                }
            }
            $targets = [ordered]@{}
            foreach ($write in $definition.Footprint) { $targets[(Get-LocationId -Key $write.Key -ValueName $write.ValueName)] = $write }
            foreach ($id in @($wanted.Keys)) { if (-not $targets.Contains($id)) { $targets[$id] = $wanted[$id] } }
            foreach ($id in @($targets.Keys)) {
                $want = $null
                if ($wanted.ContainsKey($id)) { $want = $wanted[$id] }
                # A value the state sets but the registry lacks still gets a row; one it removes does not.
                if (-not $locations.ContainsKey($id) -and ($null -eq $want -or $want.Absent -or $want.Loose)) { continue }
                $location = Get-PolicyLocation -Table $locations -Key $targets[$id].Key -ValueName $targets[$id].ValueName
                Add-LocationPolicy -Location $location -Policy $policy -Via Admx
                if ($null -ne $want) { $location.Expected[$policy.Name] = $want }
                $placed[$policy.Name] = $true
            }
            foreach ($listKey in $definition.ListKeys) {
                $claimKey = (Get-KeyPath -Key $listKey).ToLowerInvariant()
                if (-not $listClaims.ContainsKey($claimKey)) { $listClaims[$claimKey] = [System.Collections.Generic.List[object]]::new() }
                $listClaims[$claimKey].Add([pscustomobject]@{ Policy = $policy; Filled = $filled -contains $claimKey })
            }
            if ($policy.RedirectKey) {
                $claimKey = (Get-KeyPath -Key $policy.RedirectKey).ToLowerInvariant()
                if (-not $admxClaims.ContainsKey($claimKey)) { $admxClaims[$claimKey] = [System.Collections.Generic.List[object]]::new() }
                $admxClaims[$claimKey].Add($policy)
            }
        }
        elseif ($policy.AdmxBacked -and $policy.RedirectKey) {
            $table = if ($policy.Leftover) { $leftoverClaims } else { $claims }
            $claimKey = (Get-KeyPath -Key $policy.RedirectKey).ToLowerInvariant()
            if (-not $table.ContainsKey($claimKey)) { $table[$claimKey] = [System.Collections.Generic.List[object]]::new() }
            $table[$claimKey].Add($policy)
        }
    }

    # Every value under the key an ADMX list element fills is an item of that list. Where
    # the state gives the list, an item it does not hold is one the MDM removes.
    if ($listClaims.Count -gt 0) {
        $gone = [pscustomobject]@{ Text = $null; Absent = $true; Loose = $false }
        foreach ($location in @($locations.Values)) {
            $claimKey = $location.Key.ToLowerInvariant()
            if (-not $listClaims.ContainsKey($claimKey)) { continue }
            foreach ($claim in $listClaims[$claimKey]) {
                Add-LocationPolicy -Location $location -Policy $claim.Policy -Via Admx
                if ($claim.Filled -and -not $location.Expected.ContainsKey($claim.Policy.Name)) { $location.Expected[$claim.Policy.Name] = $gone }
                $placed[$claim.Policy.Name] = $true
            }
        }
    }
    $unplaced = @($Mdm | Where-Object { -not $placed[$_.Name] })

    $switchState = if ($MdmWinsOverGp) { 'on' } else { 'off' }
    $translatedMatch = 0
    $translatedDiffer = 0
    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($location in $locations.Values) {
        $live = Get-LiveValue -Root $Root -Key $location.Key -Name $location.ValueName
        $applied = @($location.Applied | Sort-Object -Property Precedence)
        $cached = $location.Cached.ToArray()
        $preferred = $location.Preferred.ToArray()
        # An external MDM before Windows' own provisioning, when both write one value.
        $active = @($location.Mdm | Where-Object { -not $_.Leftover } | Sort-Object -Property { $_.SourceKind -eq 'Windows' })
        $leftovers = @($location.Mdm | Where-Object { $_.Leftover })
        $notes = [System.Collections.Generic.List[string]]::new()

        $gpValue = $null; $gpo = $null; $gpSource = $null; $overridden = $null
        if ($applied.Count -gt 0) {
            $gpValue = $applied[0].Value
            $gpo = $applied[0].GpoName
            $gpSource = 'Registry policy'
            $losers = @($applied | Select-Object -Skip 1 | ForEach-Object { $_.GpoName } | Select-Object -Unique)
            if ($losers.Count -gt 0) { $overridden = $losers -join '; ' }
        }
        elseif ($preferred.Count -gt 0) {
            $gpValue = $preferred[0].Value
            $gpo = $preferred[0].GpoName
            $gpSource = 'Preferences'
        }
        elseif ($cached.Count -gt 0) {
            $gpValue = $cached[0].Value
            $gpo = (@($cached | ForEach-Object { $_.GpoName } | Select-Object -Unique) -join '; ')
            $gpSource = 'GPO, not applied'
        }
        $gpApplies = $applied.Count -gt 0 -or $preferred.Count -gt 0

        # When the MDM sends an ADMX state that cannot be translated, the value it put in the
        # registry is the one to compare a GPO's value with.
        $againstLive = 'the registry does not hold the value'
        if ($null -ne $live) {
            if ($live -eq $gpValue) { $againstLive = 'the GPO wants the value the registry holds' }
            else { $againstLive = ('the GPO wants {0}, the registry holds {1}' -f $gpValue, $live) }
        }

        $policy = $null
        if ($active.Count -gt 0) {
            $policy = $active[0]
            if ($active.Count -gt 1) {
                $notes.Add(('{0} MDM settings write this value: {1}.' -f $active.Count, (Format-NameList -Name ($active | ForEach-Object { $_.Name }))))
            }
        }
        $mdmValue = $null
        $admx = $false
        $expected = $null
        $untranslated = $null
        if ($null -ne $policy) {
            $mdmValue = Format-MdmValue -Value $policy.Value
            if ($location.Expected.ContainsKey($policy.Name)) { $expected = $location.Expected[$policy.Name] }
            # An ADMX state is compared as a value once its definition says what it means here.
            $admx = (Test-AdmxState -Value $policy.Value) -and $null -eq $expected
            if ($admx -and $null -ne $AdmxIndex) {
                $untranslated = if ($definitions.ContainsKey($policy.Name)) {
                    'Its ADMX definition does not say what the state writes here.'
                }
                elseif ($unresolved.ContainsKey($policy.Name)) {
                    'Its ADMX definition was not found: {0}.' -f $unresolved[$policy.Name]
                }
            }
        }
        $claimants = @(Find-KeyClaim -Claim $claims -Key $location.Key)
        $oldClaimants = @(Find-KeyClaim -Claim $leftoverClaims -Key $location.Key)
        # Whatever explains the row when no active MDM setting writes the value.
        $explainedBy = @()
        $matchedBy = $null

        if ($null -ne $policy) {
            $matchedBy = if ($location.Via[$policy.Name] -eq 'Admx') { 'Admx' } else { 'Value' }
            if ($gpApplies) {
                if ($admx) {
                    $verdict = 'Both'
                    $notes.Add(('The MDM sends an ADMX state, not a value; {0}.' -f $againstLive))
                }
                elseif ($null -ne $expected) {
                    if (Test-ExpectedValue -Expected $expected -Value $gpValue) { $verdict = 'Agree' }
                    else {
                        $verdict = 'Conflict'
                        $holder = 'neither side'
                        if ($null -ne $live -and $live -eq $gpValue) { $holder = 'Group Policy' }
                        elseif (Test-ExpectedValue -Expected $expected -Value $live) { $holder = $policy.Source }
                        $notes.Add(('The registry holds the value of {0}. MDMWinsOverGP is {1}.' -f $holder, $switchState))
                    }
                }
                elseif ($gpValue -eq $policy.Value) {
                    $verdict = 'Agree'
                }
                else {
                    $verdict = 'Conflict'
                    $holder = 'neither side'
                    if ($live -eq $gpValue) { $holder = 'Group Policy' }
                    elseif ($live -eq $policy.Value) { $holder = $policy.Source }
                    $notes.Add(('The registry holds the value of {0}. MDMWinsOverGP is {1}.' -f $holder, $switchState))
                }
            }
            elseif ($cached.Count -gt 0) {
                $verdict = 'OverriddenByMdm'
                $comparison = if ($admx) { $againstLive }
                elseif ($null -ne $expected) {
                    if (Test-ExpectedValue -Expected $expected -Value $gpValue) { 'both set the same value' } else { 'the values differ' }
                }
                elseif ($gpValue -eq $policy.Value) { 'both set the same value' }
                else { 'the values differ' }
                $notes.Add(('The GPO sets it, but {0} does and Group Policy did not apply it; {1}. MDMWinsOverGP is {2}.' -f
                        $policy.Source, $comparison, $switchState))
            }
            else {
                $verdict = 'MdmOnly'
                if ($null -ne $expected) {
                    if (Test-ExpectedValue -Expected $expected -Value $live) { $translatedMatch++ }
                    else {
                        $translatedDiffer++
                        if ($null -eq $live) { $notes.Add('The registry does not hold the value the MDM''s ADMX state means here.') }
                        else { $notes.Add('The registry holds a different value from the one the MDM''s ADMX state means: something wrote it after the MDM did.') }
                    }
                }
                elseif (-not $admx -and $null -ne $live -and $live -ne $policy.Value) {
                    $notes.Add('The registry holds a different value: something wrote it after the MDM did.')
                }
            }
            if ($untranslated) { $notes.Add($untranslated) }
        }
        elseif ($gpApplies) {
            $verdict = 'GpOnly'
            if ($null -ne $live -and $live -ne $gpValue) {
                $notes.Add('The registry holds a different value: something wrote it after Group Policy did.')
            }
            if ($claimants.Count -gt 0) {
                $notes.Add(('MDM ADMX settings also write under this key: {0}.' -f (Format-NameList -Name ($claimants | ForEach-Object { $_.Name }))))
            }
            if ($leftovers.Count -gt 0) {
                $notes.Add(('PolicyManager also lists {0} for this value, but no MDM applies it now.' -f (Format-NameList -Name ($leftovers | ForEach-Object { $_.Name }))))
            }
        }
        elseif ($cached.Count -gt 0) {
            if ($claimants.Count -gt 0) {
                $verdict = 'OverriddenByMdm'
                $matchedBy = 'Key'
                $explainedBy = $claimants
                $notes.Add(('The GPO sets it, but Group Policy did not apply it; {0}. Matched by key only: MDM ADMX settings write under this key, which is weaker evidence than a match on the value. MDMWinsOverGP is {1}.' -f
                        $againstLive, $switchState))
            }
            elseif ($leftovers.Count -gt 0 -or $oldClaimants.Count -gt 0) {
                $verdict = 'NotApplied'
                $matchedBy = if ($leftovers.Count -gt 0) { if ($location.Via[$leftovers[0].Name] -eq 'Admx') { 'Admx' } else { 'Value' } } else { 'Key' }
                $explainedBy = @(if ($leftovers.Count -gt 0) { $leftovers } else { $oldClaimants })
                $notes.Add(('The GPO sets it, but Group Policy did not apply it. PolicyManager still lists an MDM setting for it that no MDM applies any more; MDMWinsOverGP is {0}, and a leftover like this can still keep the GPO setting from applying.' -f
                        $switchState))
            }
            else {
                $verdict = 'NotApplied'
                $notes.Add('The GPO sets it, but Group Policy did not apply it, and no MDM setting writes it. A client-side extension may have failed; check the Group Policy operational log.')
            }
        }
        elseif ($location.Key -like 'SOFTWARE\Policies\Microsoft\Windows\Wireless\*') {
            $verdict = 'GpOnly'
            $gpSource = 'Wireless profile'
            $notes.Add('Written by the Wireless Group Policy extension, which RSoP does not list value by value.')
        }
        elseif ($claimants.Count -gt 0) {
            $verdict = 'MdmOnly'
            $matchedBy = 'Key'
            $explainedBy = $claimants
            if ($claimants.Count -gt 1) {
                $notes.Add(('Matched by key only: one of the {0} MDM ADMX settings in MdmSetting writes under this key.' -f $claimants.Count))
            }
            else {
                $notes.Add('Matched by key only: the MDM ADMX setting in MdmSetting writes under this key.')
            }
        }
        elseif ($leftovers.Count -gt 0 -or $oldClaimants.Count -gt 0) {
            $verdict = 'Leftover'
            $matchedBy = if ($leftovers.Count -gt 0) { if ($location.Via[$leftovers[0].Name] -eq 'Admx') { 'Admx' } else { 'Value' } } else { 'Key' }
            $explainedBy = @(if ($leftovers.Count -gt 0) { $leftovers } else { $oldClaimants })
            $notes.Add($leftoverNote)
        }
        else {
            $verdict = 'Unclaimed'
            $notes.Add('None of the sources sets it: a script, an app, another management tool, or a Windows default.')
        }

        if ($matchedBy -eq 'Admx') { $notes.Add('Matched through the ADMX definition of the MDM setting, which writes this value.') }

        # ADMX settings whose definitions were read, and leave this value out, do not claim it.
        if ($null -eq $policy -and $explainedBy.Count -eq 0 -and $leftovers.Count -eq 0 -and $admxClaims.ContainsKey($location.Key.ToLowerInvariant())) {
            $notes.Add(('MDM ADMX settings write under this key, but their ADMX definitions do not include this value: {0}.' -f
                    (Format-NameList -Name ($admxClaims[$location.Key.ToLowerInvariant()] | ForEach-Object { $_.Name }))))
        }

        $valueLabel = if ($location.ValueName) { $location.ValueName } else { '(Default)' }
        $setting = "$($location.Key)\$valueLabel"
        if ($null -ne $policy) { $setting = $policy.Name }
        elseif ($leftovers.Count -eq 1 -and $verdict -eq 'Leftover') { $setting = $leftovers[0].Name }

        $mdmSetting = $null; $mdmSource = $null; $mdmSourceKind = $null
        if ($null -ne $policy) {
            $mdmSetting = (@($active | ForEach-Object { $_.Name }) -join '; ')
            $mdmSource = $policy.Source
            $mdmSourceKind = $policy.SourceKind
        }
        elseif ($explainedBy.Count -gt 0) {
            $mdmSetting = (@($explainedBy | ForEach-Object { $_.Name } | Select-Object -Unique) -join '; ')
            $mdmSource = $explainedBy[0].Source
            $mdmSourceKind = $explainedBy[0].SourceKind
        }

        # The Group Policy name of the value: from the MDM setting's own ADMX policy, or
        # else from every ADMX policy that writes it.
        $named = @()
        $tied = @(@($active) + @($leftovers) | Where-Object { $definitions.ContainsKey($_.Name) })
        if ($tied.Count -gt 0) { $named = @($definitions[$tied[0].Name]) }
        elseif ($null -ne $AdmxIndex) { $named = @(Find-AdmxDefinition -Index $AdmxIndex -Key $location.Key -ValueName $location.ValueName) }
        $admxPolicy = $null; $displayName = $null
        if ($named.Count -gt 0) {
            $admxPolicy = Format-NameList -Name @($named | ForEach-Object { $_.Label })
            $titles = @($named | Where-Object { $_.DisplayName } | ForEach-Object { $_.DisplayName })
            if ($titles.Count -gt 0) { $displayName = Format-NameList -Name $titles }
        }

        $row = ConvertTo-PolicySourceRow -Property @{
            Verdict           = $verdict
            Setting           = $setting
            LiveValue         = $live
            GpValue           = $gpValue
            Gpo               = $gpo
            OverriddenGpo     = $overridden
            GpSource          = $gpSource
            MdmSetting        = $mdmSetting
            MdmValue          = $mdmValue
            MdmSource         = $mdmSource
            MdmSourceKind     = $mdmSourceKind
            MatchedBy         = $matchedBy
            RegistryPath      = "HKLM\$($location.Key)\$valueLabel"
            Note              = $(if ($notes.Count -gt 0) { $notes -join ' ' } else { $null })
            AdmxPolicy        = $admxPolicy
            PolicyDisplayName = $displayName
            MdmRegistryValue  = $(if ($null -ne $expected) { Format-ExpectedValue -Expected $expected } else { $null })
        }
        $names = @(@($active) + @($leftovers) | ForEach-Object { $_.Name })
        $results.Add([pscustomobject]@{
                Row         = $row
                Policies    = $names
                HasGp       = ($applied.Count + $cached.Count + $preferred.Count) -gt 0
                Blocked     = @($names | Where-Object { $location.Via[$_] -eq 'Block' })
                ViaRedirect = $names.Count -eq 1 -and $location.Via[$names[0]] -eq 'Redirect'
            })
    }

    # One setting, one row: a setting that writes one value and blocks Group Policy at
    # another keeps the row with Group Policy in it, and that row's note says where the
    # MDM's own value is. Values an ADMX definition ties a setting to keep their own rows.
    $withGp = @{}
    foreach ($result in $results) {
        if ($result.HasGp) { foreach ($name in $result.Blocked) { $withGp[$name] = $result } }
    }
    $merged = @{}
    foreach ($result in $results) {
        if (-not $result.HasGp -and $result.ViaRedirect -and $withGp.ContainsKey($result.Policies[0])) {
            $kept = $withGp[$result.Policies[0]].Row
            $shown = if ($null -ne $result.Row.LiveValue) { $result.Row.LiveValue } else { 'not set' }
            $where = 'The MDM writes its own value to {0}: {1}.' -f $result.Row.RegistryPath, $shown
            $kept.Note = if ($kept.Note) { "$($kept.Note) $where" } else { $where }
            $merged[$result.Row.RegistryPath] = $true
        }
    }
    foreach ($result in $results) {
        if (-not $merged.ContainsKey($result.Row.RegistryPath)) { $result.Row }
    }

    foreach ($policy in $unplaced) {
        $path = $null
        $admxPolicy = $null; $displayName = $null
        if ($definitions.ContainsKey($policy.Name)) {
            $admxPolicy = $definitions[$policy.Name].Label
            $displayName = $definitions[$policy.Name].DisplayName
        }
        if ($policy.RedirectKey) {
            $path = 'HKLM\' + (Get-KeyPath -Key $policy.RedirectKey)
            $note = 'ADMX-backed: writes one or more values under this key.'
            if ($definitions.ContainsKey($policy.Name)) { $note = 'ADMX-backed: none of the values its ADMX definition writes is in the registry.' }
            elseif ($unresolved.ContainsKey($policy.Name)) { $note += (' Its ADMX definition was not found: {0}.' -f $unresolved[$policy.Name]) }
            if ($gpKeys.ContainsKey((Get-KeyPath -Key $policy.RedirectKey).ToLowerInvariant())) {
                $note += ' Group Policy also sets values under this key.'
            }
        }
        else {
            $note = 'No registry value: Windows reads this setting from PolicyManager.'
        }
        if ($policy.Leftover) { $note = "$leftoverNote $note" }

        ConvertTo-PolicySourceRow -Property @{
            Verdict           = $(if ($policy.Leftover) { 'Leftover' } else { 'MdmOnly' })
            Setting           = $policy.Name
            MdmSetting        = $policy.Name
            MdmValue          = Format-MdmValue -Value $policy.Value
            MdmSource         = $policy.Source
            MdmSourceKind     = $policy.SourceKind
            RegistryPath      = $path
            Note              = $note
            AdmxPolicy        = $admxPolicy
            PolicyDisplayName = $displayName
        }
    }

    if ($null -ne $AdmxIndex) {
        $tally = (@($found.Keys | Sort-Object | ForEach-Object { '{0} {1}' -f $_, $found[$_] }) -join ', ')
        if (-not $tally) { $tally = 'none' }
        Write-LogEntry -Message ('ADMX-backed MDM settings by how their ADMX policy was found: {0}. Where only the MDM writes a value, the value its state means matches the registry {1} times and differs {2} times.' -f
            $tally, $translatedMatch, $translatedDiffer)
    }
}

function Select-PolicySource {
    <#
        .SYNOPSIS
            The rows the caller asked for, most important verdict first.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Row,

        [Parameter()]
        [AllowNull()]
        [string[]]$Filter,

        [Parameter()]
        [AllowNull()]
        [string[]]$Verdict,

        [Parameter()]
        [switch]$IncludeWindowsInternal
    )

    $selected = foreach ($candidate in $Row) {
        if (-not $IncludeWindowsInternal -and $candidate.Verdict -eq 'MdmOnly' -and $candidate.MdmSourceKind -eq 'Windows') { continue }
        if ($Verdict -and $Verdict -notcontains $candidate.Verdict) { continue }
        if ($Filter) {
            $matched = $false
            foreach ($pattern in $Filter) {
                foreach ($text in @($candidate.Setting, $candidate.RegistryPath, $candidate.MdmSetting, $candidate.Gpo, $candidate.AdmxPolicy, $candidate.PolicyDisplayName)) {
                    if ($text -and $text -like $pattern) { $matched = $true; break }
                }
                if ($matched) { break }
            }
            if (-not $matched) { continue }
        }
        $candidate
    }

    if ($null -eq $selected) { return }
    @($selected) | Sort-Object -Property @{ Expression = { $VerdictRank[$_.Verdict] } }, Setting
}

$machine = $null
try {
    $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
    $script:LogFile = Initialize-LogFile -Directory $LogDirectory -Name $scriptName -MaxSizeBytes $MaxLogSizeBytes
    $timer = [Diagnostics.Stopwatch]::StartNew()
    Write-LogEntry -Message "Started. PowerShell $($PSVersionTable.PSVersion); host: $(if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' })."

    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Get-PolicySource runs on Windows only: it reads the Windows registry and RSoP data.'
    }
    if (-not (Test-Elevated)) {
        throw 'Run this from an elevated PowerShell. The Group Policy results (RSoP) and the GPO cache can only be read by an administrator.'
    }

    # The 64-bit view, so a 32-bit PowerShell reads the same keys Windows does.
    $machine = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)

    Write-Progress -Activity 'Get-PolicySource' -Status 'Reading MDM policy'
    $sources = Get-EnrollmentSource -Root $machine
    $mdm = @(Get-MdmPolicy -Root $machine -Source $sources)
    $mdmWinsOverGp = (Get-LiveValue -Root $machine -Key "$PolicyManagerPath\current\device\ControlPolicyConflict" -Name 'MDMWinsOverGP') -eq '1'
    Write-LogEntry -Message ('MDM settings: {0}. MDMWinsOverGP: {1}.' -f $mdm.Count, $mdmWinsOverGp)

    # ADMX definitions turn ADMX states into the values they mean. Without them the run
    # still works: states are compared with the registry and ADMX settings matched by key.
    Write-Progress -Activity 'Get-PolicySource' -Status 'Reading ADMX definitions'
    $admxIndex = $null
    try {
        $admxTimer = [Diagnostics.Stopwatch]::StartNew()
        $culture = [cultureinfo]::CurrentUICulture
        $languages = @(@($culture.Name, $culture.Parent.Name, 'en-US') | Where-Object { $_ } | Select-Object -Unique)
        # Where Windows keeps ingested ADMX files is not documented; these are the candidates.
        $ingestedDirectories = @()
        try {
            $ingestedDirectories = @([IO.Directory]::GetDirectories((Join-Path -Path $env:ProgramData -ChildPath 'Microsoft'), 'PolicyManager*'))
        }
        catch {
            Write-LogEntry -Message "Ingested ADMX: %ProgramData%\Microsoft could not be listed ($($_.Exception.GetType().Name)); only the registry is searched." -Level WARN
        }
        $admxIndex = Import-AdmxDefinition -Directory $PolicyDefinitionsDirectory -IngestedDirectory $ingestedDirectories -Root $machine -Language $languages
        if ($admxIndex.Failed.Count -gt 0) {
            $failures = @($admxIndex.Failed.Keys | Sort-Object | ForEach-Object { '{0}.admx ({1})' -f $_, $admxIndex.Failed[$_].TrimEnd('.') })
            Write-Warning ('{0} ADMX file(s) in {1} could not be read, so the settings they define are compared as without ADMX definitions: {2}' -f
                $failures.Count, $PolicyDefinitionsDirectory, ($failures -join '; '))
        }
        Write-LogEntry -Message ('ADMX definitions read in {0:N1} s: {1} files, {2} not readable, {3} without ADML; ingested documents: {4} from files, {5} from the registry.' -f
            $admxTimer.Elapsed.TotalSeconds, $admxIndex.Files.Count, $admxIndex.Failed.Count, $admxIndex.WithoutAdml,
            $admxIndex.IngestedFrom['File'], $admxIndex.IngestedFrom['Registry'])
    }
    catch {
        $admxIndex = $null
        Write-Warning "ADMX definitions could not be read, so ADMX states are compared with the registry and ADMX settings matched by key: $($_.Exception.Message)"
        Write-LogEntry -Message "ADMX definitions: $($_.Exception.Message)" -Level WARN
    }

    Write-Progress -Activity 'Get-PolicySource' -Status 'Reading Group Policy results'
    # The ADMX policy 'Turn off Resultant Set of Policy logging' sets RSoPLogging to 0.
    if ((Get-LiveValue -Root $machine -Key "$PoliciesPath\Microsoft\Windows\System" -Name 'RSoPLogging') -eq '0') {
        throw ('RSoP logging is turned off on this device (policy "Turn off Resultant Set of Policy logging"), so ' +
            'the applied Group Policy cannot be read. Without it every Group Policy setting would look missing.')
    }
    try {
        $rsop = Get-AppliedGroupPolicy
    }
    catch {
        throw "Could not read the Group Policy results from WMI (root\rsop\computer): $($_.Exception.Message)"
    }
    $appliedGpo = @{}
    foreach ($gpo in $rsop.Gpo.Values) {
        if ($gpo.Applied -and $gpo.Domain -and $gpo.Guid) { $appliedGpo[$gpo.Guid] = $gpo.Name }
    }
    Write-LogEntry -Message ('Applied registry policy entries: {0}; domain GPOs applied: {1}.' -f $rsop.Entry.Count, $appliedGpo.Count)

    # The cache and the Preferences history add to RSoP; without them the run is still useful.
    Write-Progress -Activity 'Get-PolicySource' -Status 'Reading the GPO cache'
    $cached = @()
    if ($appliedGpo.Count -gt 0 -and -not (Test-Path -LiteralPath $GpoCacheDirectory -PathType Container)) {
        Write-Warning ("No GPO cache at $GpoCacheDirectory. Settings a GPO holds but did not apply - OverriddenByMdm " +
            'and NotApplied - cannot be found.')
    }
    try {
        $cached = @(Get-GpoCacheEntry -Directory $GpoCacheDirectory -AppliedGpo $appliedGpo)
    }
    catch {
        Write-Warning "The GPO cache could not be read, so OverriddenByMdm and NotApplied cannot be found: $($_.Exception.Message)"
        Write-LogEntry -Message "GPO cache: $($_.Exception.Message)" -Level WARN
    }
    $preferences = @()
    try {
        $preferences = @(Get-PreferenceRegistryItem -Directory $PreferencesHistoryDirectory -AppliedGpo $appliedGpo)
    }
    catch {
        Write-Warning "The Group Policy Preferences history could not be read, so its registry items show as Unclaimed: $($_.Exception.Message)"
        Write-LogEntry -Message "Preferences history: $($_.Exception.Message)" -Level WARN
    }
    Write-LogEntry -Message ('GPO cache entries: {0}; Preferences registry items: {1}.' -f $cached.Count, $preferences.Count)

    Write-Progress -Activity 'Get-PolicySource' -Status 'Matching the sources'
    $rows = @(Resolve-PolicySource -Mdm $mdm -GpApplied $rsop.Entry -GpCached $cached -Preference $preferences -Root $machine -MdmWinsOverGp $mdmWinsOverGp -AdmxIndex $admxIndex)
    $result = @(Select-PolicySource -Row $rows -Filter $Filter -Verdict $Verdict -IncludeWindowsInternal:$IncludeWindowsInternal)
    Write-Progress -Activity 'Get-PolicySource' -Completed

    $summary = (@($rows | Group-Object -Property Verdict | Sort-Object -Property { $VerdictRank[$_.Name] } |
                ForEach-Object { '{0} {1}' -f $_.Name, $_.Count }) -join ', ')
    Write-LogEntry -Message ('Finished in {0:N1} s. All settings: {1}. Returned: {2}.' -f $timer.Elapsed.TotalSeconds, $summary, $result.Count)

    $result
    exit $ExitSuccess
}
catch {
    $message = "Get-PolicySource failed: $($_.Exception.Message)"
    Write-LogEntry -Message "$message Line $($_.InvocationInfo.ScriptLineNumber)." -Level ERROR
    Write-Error -Exception $_.Exception -Message $message -ErrorAction Continue
    exit $ExitFailure
}
finally {
    if ($null -ne $machine) { $machine.Dispose() }
}

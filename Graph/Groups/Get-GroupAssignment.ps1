# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/zenpachi-alt/endpoint-engineering

#Requires -Version 5.1

<#
.SYNOPSIS
    Finds everything in Microsoft Intune that is assigned to an Entra ID group,
    so the effect of changing the group can be seen before it is changed.

.DESCRIPTION
    Intune keeps each assignment on the policy, app or script it belongs to,
    and neither Intune nor Graph can be asked for what a group is assigned. So
    the script reads every object in the sources below, reads each object's
    assignments, and returns one record for each assignment that names the
    group. Nothing is changed in the tenant. Every call is an HTTP GET.

    The group is found by its exact display name, or by object ID with
    -GroupId. Graph does not keep display names unique, so a name that belongs
    to more than one group stops the run and lists their object IDs. None is
    chosen. An object ID that no group has is searched for anyway, because an
    assignment can outlive the group it names.

    The groups the group is nested in are searched as well, since their
    assignments reach its members. Those records have Relationship Inherited
    and name the parent in AssignedGroup.

    Assignment on each record says what the group does there:

      Include     The object is deployed to the group.
      Exclude     The group is held out of the object. Removing the group from
                  an exclusion widens the deployment.
      RoleMember  The group's members hold the Intune role.
      RoleScope   The Intune role can manage the group's members.

    An empty result can be acted on, so what was searched matters as much as
    what was found. A coverage report lists every source with one of these
    statuses, and is written on every run:

      Complete       Every object in the source was read.
      Partial        Part of the source could not be read, or an assignment
                     names a target this script cannot read. Detail says which.
      Failed         The source could not be read at all.
      NotSearched    -Category left the source out.
      NotApplicable  Only for parent groups, of a group that does not exist.

    The sources, by -Category, all called on beta. Most exist nowhere else, and
    deviceConfigurations returns its full set of profile types only there:

      ConfigurationProfiles deviceManagement/deviceConfigurations
                            deviceManagement/configurationPolicies
                            deviceManagement/groupPolicyConfigurations
                            deviceManagement/intents
      CompliancePolicies    deviceManagement/deviceCompliancePolicies
      Scripts               deviceManagement/deviceHealthScripts
                            deviceManagement/deviceManagementScripts
                            deviceManagement/deviceShellScripts
                            deviceManagement/deviceCustomAttributeShellScripts
      WindowsUpdates        deviceManagement/windowsFeatureUpdateProfiles
                            deviceManagement/windowsQualityUpdatePolicies
                            deviceManagement/windowsQualityUpdateProfiles
                            deviceManagement/windowsDriverUpdateProfiles
      Apps                  deviceAppManagement/mobileApps
                            deviceAppManagement/mobileAppConfigurations
                            deviceAppManagement/targetedManagedAppConfigurations
                            deviceAppManagement/iosManagedAppProtections
                            deviceAppManagement/androidManagedAppProtections
                            deviceAppManagement/windowsManagedAppProtections
      Enrollment            deviceManagement/deviceEnrollmentConfigurations
                            deviceManagement/windowsAutopilotDeploymentProfiles
                            deviceManagement/termsAndConditions
      PolicySets            deviceAppManagement/policySets
      Roles                 deviceManagement/roleAssignments
                            deviceManagement/roleScopeTags

    The group and its parents are read on v1.0.

    The run takes about one request per object in the tenant, plus one per
    source. Throttling is waited out, so a large tenant takes minutes, not
    seconds. Narrow it with -Category.

    Exit codes:
      0  Every selected source was read. Finding nothing is a result, not a
         failure.
      1  The script failed: sign-in, or a group name that is unknown or
         ambiguous. Nothing was searched.
      2  The records are returned, but part of the search could not be read,
         so they may be incomplete.

.PARAMETER GroupName
    Exact display name of the group, compared without regard to case.

.PARAMETER GroupId
    Object ID of the group. Use it when the name is shared, and for a group
    that may no longer exist.

.PARAMETER Category
    Which sources to search. Every category by default. A category left out
    needs no scope of its own, and is reported as NotSearched.

.PARAMETER OutputPath
    Existing directory for the report and the coverage report. Defaults to the
    user's temp directory. Keep it outside this repository: the files name real
    policies and groups.

.PARAMETER TenantId
    Tenant to connect to, as a GUID or a verified domain name. Optional: an
    existing Microsoft Graph session is reused when it matches.

.PARAMETER UseDeviceCode
    Sign in with the device code flow, for hosts where a browser prompt cannot
    open.

.PARAMETER MaximumRetryCount
    Attempts per Graph request, the first included, before giving up on a
    throttled or failing call.

.EXAMPLE
    .\Get-GroupAssignment.ps1 -GroupName 'Pilot devices'

    Everything assigned to the group or to a group it is nested in, with the
    report and the coverage report written to the temp directory.

.EXAMPLE
    .\Get-GroupAssignment.ps1 -GroupId '<GroupId>' -UseDeviceCode -OutputPath C:\Reports

    The same by object ID, signing in with a device code.

.EXAMPLE
    .\Get-GroupAssignment.ps1 -GroupName 'Pilot devices' -Category Apps, Scripts

    Searches apps and scripts only. The other sources are reported as
    NotSearched.

.EXAMPLE
    .\Get-GroupAssignment.ps1 -GroupName 'Pilot devices' | Where-Object Assignment -eq 'Exclude' | Format-Table ObjectType, ObjectName, AssignedGroup

    Where the group is excluded, which is where removing it would widen a
    deployment.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.0.0
    Last updated  : 2026-11-01

    PowerShell    : 5.1 or 7. No PowerShell 7 syntax is used.
    Graph scopes  : DeviceManagementConfiguration.Read.All, always. It covers
                    ConfigurationProfiles, CompliancePolicies, WindowsUpdates,
                    PolicySets and the names of assignment filters.
                    GroupMember.Read.All, always, for the group and its parents
                    (Group.Read.All or Directory.Read.All accepted when already
                    granted).
                    DeviceManagementScripts.Read.All, for Scripts.
                    DeviceManagementApps.Read.All, for Apps.
                    DeviceManagementServiceConfig.Read.All, for Enrollment.
                    DeviceManagementRBAC.Read.All, for Roles.
                    The ReadWrite equivalents are accepted where already
                    granted.
    Admin consent : Required, once per tenant, for every scope above.
    Licensing     : Microsoft Intune Plan 1. The tenant needs an active Intune
                    licence for the Graph API for Intune to respond at all.
    Modules       : Microsoft.Graph.Authentication 2.0.0 or later.
    Role required : Any Intune role that can read these objects. Read-only
                    operator roles are enough; this script never writes.
                    Reading groups: any member user, unless the tenant
                    restricts default user permissions; Directory Readers
                    otherwise.

    Endpoint      : beta, by necessity, for everything in Intune; see the
                    description. The beta contract changes without notice. A
                    change shows as a Failed or Partial source, not as a
                    missing record. v1.0 for the group and its parents.

    Scope tags    : Intune scope tags apply. Objects outside the signed-in
                    account's scope are not returned, and cannot be searched.
                    Graph gives no sign of them, so run this with an account
                    that sees every object before trusting an empty result.

    Not searched  : Anything outside Intune: Conditional Access, Entra roles,
                    enterprise apps, group-based licensing, access packages,
                    Exchange, SharePoint, Teams. Within Intune, Windows
                    Autopatch groups, which have no documented Graph API (the
                    policies and Entra groups they create are searched like any
                    other), Windows 365 provisioning policies, branding
                    profiles, eSIM activation pools, managed e-books, iOS app
                    provisioning profiles, S mode supplemental policies, and the
                    device group of an enrollment time grouping policy. This
                    script shows where a group is used in Intune. It does not
                    show that a group is safe to delete.

    Output        : The reports name real policies, groups and object IDs.
                    Treat them as tenant data: keep them out of this repository.

.LINK
    https://learn.microsoft.com/graph/api/resources/intune-graph-overview

.LINK
    https://learn.microsoft.com/graph/api/group-list-transitivememberof

.LINK
    https://learn.microsoft.com/graph/api/resources/intune-shared-deviceandappmanagementassignmenttarget

.LINK
    https://learn.microsoft.com/graph/api/resources/intune-rbac-deviceandappmanagementroleassignment
#>

[CmdletBinding(DefaultParameterSetName = 'Name')]
param (
    [Parameter(Mandatory, Position = 0, ParameterSetName = 'Name', HelpMessage = 'Exact display name of the group.')]
    [ValidateNotNullOrEmpty()]
    [string]$GroupName,

    [Parameter(Mandatory, ParameterSetName = 'Id', HelpMessage = 'Object ID (GUID) of the group.')]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$GroupId,

    [Parameter()]
    [ValidateSet('ConfigurationProfiles', 'CompliancePolicies', 'Scripts', 'WindowsUpdates', 'Apps', 'Enrollment', 'PolicySets', 'Roles')]
    [string[]]$Category = @('ConfigurationProfiles', 'CompliancePolicies', 'Scripts', 'WindowsUpdates', 'Apps', 'Enrollment', 'PolicySets', 'Roles'),

    [Parameter()]
    [ValidateScript({
            if (Test-Path -LiteralPath $_ -PathType Container) { $true }
            else { throw "OutputPath '$_' does not exist or is not a directory." }
        })]
    [string]$OutputPath = [System.IO.Path]::GetTempPath(),

    [Parameter()]
    [ValidatePattern('^([0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}|[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})$')]
    [string]$TenantId,

    [Parameter()]
    [switch]$UseDeviceCode,

    [Parameter()]
    [ValidateRange(1, 10)]
    [int]$MaximumRetryCount = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

#region Graph module
# Identical in every script under Graph/, like the Graph helpers below. The
# master copy is the one in Templates/Script-Template.ps1, and
# Templates/Script-Template.Tests.ps1 fails while any copy differs.
#
# The module is loaded here rather than declared with '#Requires -Modules',
# which costs a script its exit code. PowerShell loads a module declared that
# way before the script starts, and when the module runs code of its own while
# it loads, as this one does, a script started with -File reports 0 whatever
# it exits with.
#
# -WhatIf and -Confirm are switched off while the module loads, and restored
# after it. A script started with -File runs in the global scope, where a
# module looks up its preferences, so both would reach the Update-TypeData
# calls the module makes as it loads: -WhatIf prints a line for each, ahead of
# the script's own, and -Confirm asks about each, or fails the import where no
# one can answer.
try {
    $GraphModulePreference = $WhatIfPreference, $ConfirmPreference
    $WhatIfPreference = $false
    $ConfirmPreference = 'None'
    # 4>$null, or a run with -Verbose lists every command the module imports.
    Import-Module -Name Microsoft.Graph.Authentication -MinimumVersion 2.0.0 -ErrorAction Stop 4>$null
}
catch {
    Write-Error -Exception $_.Exception -ErrorAction Continue -Message (
        "Microsoft.Graph.Authentication 2.0.0 or later could not be loaded: $($_.Exception.Message) " +
        'If it is not installed, run: Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser')
    exit 1
}
finally {
    $WhatIfPreference, $ConfirmPreference = $GraphModulePreference
}
#endregion Graph module

$GraphBaseUri = 'https://graph.microsoft.com/v1.0'
$GraphBetaUri = 'https://graph.microsoft.com/beta'
$ConnectionOpenedHere = $false

# 2 once part of the search could not be read. The script exits with it after
# the main block, so the session is closed first.
$ExitCode = 0

#region Graph helpers
# Shared by every script under Graph/ and identical in each, so that any one of
# them still runs when copied out on its own. The master copy is the one in
# Templates/Script-Template.ps1: change it there, paste the whole region over
# every other copy, and run Invoke-Pester - Templates/Script-Template.Tests.ps1
# fails while any copy differs. Written for Windows PowerShell 5.1 and for
# Set-StrictMode -Version Latest, so it runs wherever the script does.

function Get-PropertyValue {
    <#
        .SYNOPSIS
            Reads a property that may not exist, without tripping
            Set-StrictMode. Graph omits properties that are null, and v1.0 and
            beta return different sets.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        $InputObject,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    if ($null -eq $InputObject) { return $null }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }

    return $property.Value
}

function ConvertFrom-GraphJson {
    <#
        .SYNOPSIS
            Parses a Graph response body, keeping timestamps as the text Graph
            sent wherever ConvertFrom-Json allows it.

        .DESCRIPTION
            Windows PowerShell 5.1 leaves timestamps as strings, and PowerShell
            7.5 does so with -DateKind String. PowerShell 7.0 to 7.4 always turn
            them into DateTime, so code that reads a timestamp accepts either.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Json
    )

    if ([string]::IsNullOrWhiteSpace($Json)) { return $null }

    $parameters = @{ InputObject = $Json; ErrorAction = 'Stop' }
    if ((Get-Command -Name ConvertFrom-Json).Parameters.ContainsKey('DateKind')) {
        $parameters['DateKind'] = 'String'
    }

    ConvertFrom-Json @parameters
}

function ConvertTo-UtcDateTime {
    <#
        .SYNOPSIS
            Reads a Graph timestamp as a UTC DateTime, or $null when there is
            none.

        .DESCRIPTION
            Accepts the text Graph sent, and the DateTime that PowerShell 7.0
            to 7.4 make of it. Graph sends timestamps in UTC, so text without
            an offset and a DateTime of unspecified kind are read as UTC, never
            as local time. Text that is not a timestamp throws, rather than
            passing for a missing value.
    #>
    [CmdletBinding()]
    [OutputType([datetime])]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        $Value
    )

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }

    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }

    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) {
            return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc)
        }
        return $Value.ToUniversalTime()
    }

    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor
        [System.Globalization.DateTimeStyles]::AssumeUniversal
    $parsed = [datetime]::MinValue

    if (-not [datetime]::TryParse([string]$Value, [cultureinfo]::InvariantCulture, $styles, [ref]$parsed)) {
        throw "'$Value' is not a timestamp. Graph sends ISO 8601 text such as 2026-03-01T10:15:00Z."
    }

    return $parsed
}

function Get-GraphErrorText {
    <#
        .SYNOPSIS
            Turns an error response body into "code: message", or into the
            start of the body when it is not a Graph error object.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Content
    )

    if ([string]::IsNullOrWhiteSpace($Content)) { return 'no response body' }

    try {
        $parsed = ConvertFrom-Json -InputObject $Content -ErrorAction Stop
        $graphError = Get-PropertyValue -InputObject $parsed -Name 'error'
        $code = Get-PropertyValue -InputObject $graphError -Name 'code'
        $message = Get-PropertyValue -InputObject $graphError -Name 'message'
        if ($code -or $message) { return ('{0}: {1}' -f $code, $message) }
    }
    catch {
        Write-Debug "The response body is not a Graph error object: $($_.Exception.Message)"
    }

    if ($Content.Length -gt 300) { return $Content.Substring(0, 300) }
    return $Content
}

function Get-RetryDelaySecond {
    <#
        .SYNOPSIS
            How long to wait before the next attempt: the Retry-After header
            when the service sent one, otherwise exponential backoff with
            jitter, so that parallel runs do not retry in lockstep.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param (
        [Parameter()]
        [AllowNull()]
        $ResponseHeaders,

        [Parameter(Mandatory)]
        [ValidateRange(1, 100)]
        [int]$Attempt
    )

    if ($null -ne $ResponseHeaders) {
        foreach ($key in @($ResponseHeaders.Keys)) {
            if ($key -ne 'Retry-After') { continue }

            # The value arrives as a string or as a single-element collection.
            # Five minutes is the ceiling, so a bad header cannot stall a run.
            $raw = @($ResponseHeaders[$key])[0]
            $seconds = 0
            if ([int]::TryParse([string]$raw, [ref]$seconds) -and $seconds -gt 0) {
                return [Math]::Min($seconds, 300)
            }
        }
    }

    $backoff = [int][Math]::Min([Math]::Pow(2, $Attempt), 60)
    return $backoff + (Get-Random -Minimum 0 -Maximum 3)
}

function Test-TransientFailure {
    <#
        .SYNOPSIS
            True when a request failed without an answer from Graph - a
            dropped connection, a failed name lookup, a timeout - rather than
            for a reason that would fail again, such as not being signed in.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Exception]$Exception
    )

    # Matched by name: System.Net.Http is not loaded in every Windows
    # PowerShell session, and a type literal for it would fail there.
    $transientType = @(
        'System.Net.Http.HttpRequestException'
        'System.Net.Sockets.SocketException'
        'System.Net.WebException'
        'System.IO.IOException'
        'System.TimeoutException'
        'System.Threading.Tasks.TaskCanceledException'
    )

    for ($current = $Exception; $null -ne $current; $current = $current.InnerException) {
        for ($type = $current.GetType(); $null -ne $type; $type = $type.BaseType) {
            if ($transientType -contains $type.FullName) { return $true }
        }
    }

    return $false
}

function Invoke-GraphRequestWithRetry {
    <#
        .SYNOPSIS
            Sends one Graph request and returns the parsed response, retrying
            throttled and transient failures.

        .DESCRIPTION
            The Graph SDK retries 429, 503 and 504 by itself - three times,
            honouring Retry-After - and then throws, even with
            -SkipHttpErrorCheck. A loop around that one multiplies the attempts
            and never sees the status code, so the SDK's retry is switched off
            for the length of the call and this loop is the only one. The
            previous setting is restored afterwards. The setting is
            process-wide: do not call this from parallel runspaces.

            GET is retried on 429, 500, 502, 503 and 504, and when no response
            arrives at all. POST, PATCH and DELETE are retried only on 429 and
            503, the answers that mean the service did not act on the request:
            retrying after any other failure could repeat a change that had
            already landed.

            A request that still fails throws. Data['StatusCode'] on the
            exception holds the last HTTP status, or 0 when nothing came back.

            Each retry is announced with Write-Warning, or handed to -OnRetry
            instead, for a script that keeps its own log.

            A URI on https://graph.microsoft.com reaches the SDK as a path
            relative to it, which the SDK sends to the same address. Given an
            absolute URI, Invoke-MgGraphRequest swaps the session's cloud
            environment for one with no sign-in endpoint, and keeps the swap.
            The SDK then rebuilds its HTTP client after the next
            Set-MgRequestContext, and a session signed in as a user, or with a
            certificate or secret, fails that request and every one after it
            with "Invalid URI: The format of the URI could not be determined."
            Seen in Microsoft.Graph.Authentication 2.41.0.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri,

        [Parameter()]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string]$Method = 'GET',

        [Parameter()]
        [AllowNull()]
        [hashtable]$Body,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$MaximumAttempt = 5,

        [Parameter()]
        [AllowNull()]
        [scriptblock]$OnRetry
    )

    $retryStatus = if ($Method -eq 'GET') { @(429, 500, 502, 503, 504) } else { @(429, 503) }

    # Relative, so that the SDK leaves the session's environment alone; the
    # description says why. Messages keep the URI as the caller gave it.
    $graphHost = 'https://graph.microsoft.com/'
    $requestUri = $Uri
    if ($Uri.StartsWith($graphHost, [System.StringComparison]::OrdinalIgnoreCase)) {
        $requestUri = $Uri.Substring($graphHost.Length)
    }

    # -WhatIf:$false and -Confirm:$false keep the calling script's -WhatIf or
    # -Confirm from reaching Set-MgRequestContext, which supports ShouldProcess.
    $sdkMaxRetry = (Get-MgRequestContext).MaxRetry
    if ($sdkMaxRetry -ne 0) {
        $null = Set-MgRequestContext -MaxRetry 0 -WhatIf:$false -Confirm:$false
    }

    try {
        $attempt = 0

        while ($true) {
            $attempt++

            $statusCode = 0
            $responseHeaders = $null
            $content = $null
            $failure = $null

            $request = @{
                Method                  = $Method
                Uri                     = $requestUri
                OutputType              = 'Json'
                StatusCodeVariable      = 'statusCode'
                ResponseHeadersVariable = 'responseHeaders'
                SkipHttpErrorCheck      = $true
                ErrorAction             = 'Stop'
            }
            if ($Body) { $request['Body'] = $Body }

            try {
                $content = Invoke-MgGraphRequest @request
            }
            catch {
                # Not signed in, a malformed request: repeating it cannot help.
                if (-not (Test-TransientFailure -Exception $_.Exception)) { throw }
                $failure = $_.Exception
            }

            if (-not $failure -and $statusCode -ge 200 -and $statusCode -lt 300) {
                return ConvertFrom-GraphJson -Json $content
            }

            $outcome = if ($failure) { 'No response' } else { "HTTP $statusCode" }
            $canRetry = if ($failure) { $Method -eq 'GET' } else { $retryStatus -contains $statusCode }

            if (-not $canRetry -or $attempt -ge $MaximumAttempt) {
                $detail = if ($failure) { $failure.Message } else { Get-GraphErrorText -Content $content }
                $exception = [System.Exception]::new(
                    "$outcome from $Method $Uri after $attempt attempt(s): $detail", $failure)
                $exception.Data['StatusCode'] = $statusCode
                throw $exception
            }

            $delay = Get-RetryDelaySecond -ResponseHeaders $responseHeaders -Attempt $attempt
            $notice = "$outcome from $Method $Uri. Waiting $delay second(s) before attempt $($attempt + 1) of $MaximumAttempt."
            if ($OnRetry) { & $OnRetry $notice } else { Write-Warning -Message $notice }

            Start-Sleep -Seconds $delay
        }
    }
    finally {
        if ($sdkMaxRetry -ne 0) {
            $null = Set-MgRequestContext -MaxRetry $sdkMaxRetry -WhatIf:$false -Confirm:$false
        }
    }
}

function Get-GraphCollection {
    <#
        .SYNOPSIS
            Reads every page of a Graph collection, following @odata.nextLink
            until the service stops sending one. A script that reads one page
            and stops silently under-reports.

        .DESCRIPTION
            Returns a List even for zero or one item, so Count is always right
            and ConvertTo-Json always writes an array.
    #>
    # The caller receives the List; object[] is the one-element wrapper that
    # 'return , $items' builds to stop the pipeline unrolling it.
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]], [object[]])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$MaximumAttempt = 5,

        [Parameter()]
        [AllowNull()]
        [scriptblock]$OnRetry
    )

    # ::new(), not New-Object: a List from New-Object, once stored in an object
    # property, makes PowerShell throw "Argument types do not match" in an
    # expression as ordinary as: if ($x.Items) { @($x.Items).Count } else { '' }
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    $page = 0

    while ($next) {
        $page++
        if ($page -gt 1) { Write-Verbose "Reading page $page of $(($Uri -split '\?')[0])." }

        $response = Invoke-GraphRequestWithRetry -Uri $next -MaximumAttempt $MaximumAttempt -OnRetry $OnRetry

        if ($null -eq $response -or $null -eq $response.PSObject.Properties['value']) {
            throw "GET $next returned no 'value' list, so it is not a collection."
        }

        foreach ($item in @($response.value)) { $items.Add($item) }
        $next = Get-PropertyValue -InputObject $response -Name '@odata.nextLink'
    }

    return , $items
}

function Get-MissingGraphScope {
    <#
        .SYNOPSIS
            Returns each required scope that the granted scopes satisfy neither
            directly nor through one of its broader alternatives.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Collections.IDictionary]$Scope,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Granted
    )

    foreach ($required in $Scope.Keys) {
        $satisfied = $false

        foreach ($candidate in @(@($required) + @($Scope[$required]))) {
            if ($Granted -contains $candidate) { $satisfied = $true; break }
        }

        if (-not $satisfied) { [string]$required }
    }
}

function Connect-GraphSession {
    <#
        .SYNOPSIS
            Reuses the current Microsoft Graph session when it will do, signs
            in when it will not, and proves the session holds every scope the
            script needs. Returns $true when it signed in, so the script
            disconnects only a session it opened.

        .DESCRIPTION
            -Scope maps each scope the script requests to the broader scopes
            that also satisfy it:

                [ordered]@{
                    'DeviceManagementManagedDevices.Read.All' =
                        @('DeviceManagementManagedDevices.ReadWrite.All')
                }

            Sign-in requests only the keys, the narrowest set. An existing
            session holding a broader alternative is accepted, so an
            administrator who already consented to ReadWrite is not asked to
            consent to Read as well.

            A delegated session for another tenant, or without a needed scope,
            is replaced by a new sign-in. An app-only session is never
            replaced: the function fails and names the permission to grant.

            With -UseDeviceCode, the code and the address to enter it at are
            shown on the information stream while the sign-in waits for them.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Collections.IDictionary]$Scope,

        [Parameter()]
        [AllowEmptyString()]
        [string]$TenantId,

        [Parameter()]
        [switch]$UseDeviceCode
    )

    $context = Get-MgContext

    if ($context -and $TenantId -and $context.TenantId -ne $TenantId -and
        $context.Account -notlike "*@$TenantId") {
        Write-Verbose "The current Graph session is for tenant '$($context.TenantId)'; signing in to '$TenantId' instead."
        $context = $null
    }

    if ($context) {
        $granted = @($context.Scopes | Where-Object { $_ })
        $missing = @(Get-MissingGraphScope -Scope $Scope -Granted $granted)
        $identity = if ($context.Account) { $context.Account } else { $context.AppName }

        if ($missing.Count -eq 0) {
            Write-Verbose "Reusing the Graph session of '$identity' in tenant '$($context.TenantId)'."
            return $false
        }

        if ([string]$context.AuthType -ne 'Delegated') {
            if ($granted.Count -eq 0) {
                Write-Warning "The $($context.AuthType) Graph session of '$identity' lists no permissions, so they cannot be verified. A missing one will fail as HTTP 403."
                return $false
            }

            throw "The $($context.AuthType) Graph session of '$identity' lacks $($missing -join ', '). Grant the application permission with admin consent, or run Disconnect-MgGraph and rerun the script to sign in as a user."
        }

        Write-Warning "The current Graph session lacks $($missing -join ', '). Signing in again with the scopes this script needs."
    }

    $connectParameters = @{
        Scopes      = [string[]]@($Scope.Keys)
        ErrorAction = 'Stop'
    }
    if ((Get-Command -Name Connect-MgGraph).Parameters.ContainsKey('NoWelcome')) {
        $connectParameters['NoWelcome'] = $true
    }
    if ($TenantId) { $connectParameters['TenantId'] = $TenantId }
    if ($UseDeviceCode) {
        $connectParameters['UseDeviceCode'] = $true
        Write-Verbose 'Starting device code sign-in. A code and a URL follow.'
    }

    # Connect-MgGraph writes what it has to tell the person signing in - the
    # device code and where to enter it, or the welcome where -NoWelcome is
    # missing - to the output stream, as data. Discarded, the code never shows
    # and the sign-in waits until it times out. Passed on as information, each
    # line shows the moment it is written, while the sign-in still waits, and
    # stays out of what this function returns.
    Connect-MgGraph @connectParameters | ForEach-Object {
        Write-Information -MessageData $_ -InformationAction Continue
    }

    $context = Get-MgContext
    if (-not $context) { throw 'Connect-MgGraph finished, but no Graph session is available.' }

    # Consent can be partial: sign-in succeeds with whatever was granted.
    $granted = @($context.Scopes | Where-Object { $_ })
    $missing = @(Get-MissingGraphScope -Scope $Scope -Granted $granted)

    if ($missing.Count -gt 0) {
        try {
            $null = Disconnect-MgGraph -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to disconnect from Microsoft Graph: $($_.Exception.Message)"
        }

        throw "Signed in, but consent does not cover $($missing -join ', '). An administrator can grant it for the tenant. Granted: $($granted -join ', ')."
    }

    Write-Verbose "Connected as '$($context.Account)' in tenant '$($context.TenantId)'."
    return $true
}
#endregion Graph helpers

function Get-AssignmentSource {
    <#
        .SYNOPSIS
            Every Graph collection the script searches.

        .DESCRIPTION
            Read says how an object gives up its assignments:

              Assignments  GET {object}/assignments
              Expand       GET {object}?$expand=assignments. The macOS script
                           collections: the documented assignments path of
                           deviceShellScripts answers HTTP 400, "No OData route
                           exists", and returns the same list expanded.
              Role         GET {object}. A role assignment has no assignment
                           targets: it lists groups in properties of its own.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param ()

    $rows = @(
        @{ Category = 'ConfigurationProfiles'; Label = 'Device configuration profile'; Path = 'deviceManagement/deviceConfigurations' }
        @{ Category = 'ConfigurationProfiles'; Label = 'Settings catalog policy'; Path = 'deviceManagement/configurationPolicies' }
        @{ Category = 'ConfigurationProfiles'; Label = 'Administrative template'; Path = 'deviceManagement/groupPolicyConfigurations' }
        @{ Category = 'ConfigurationProfiles'; Label = 'Security baseline intent'; Path = 'deviceManagement/intents' }
        @{ Category = 'CompliancePolicies'; Label = 'Compliance policy'; Path = 'deviceManagement/deviceCompliancePolicies' }
        @{ Category = 'Scripts'; Label = 'Remediation'; Path = 'deviceManagement/deviceHealthScripts' }
        @{ Category = 'Scripts'; Label = 'Windows platform script'; Path = 'deviceManagement/deviceManagementScripts' }
        @{ Category = 'Scripts'; Label = 'macOS shell script'; Path = 'deviceManagement/deviceShellScripts'; Read = 'Expand' }
        @{ Category = 'Scripts'; Label = 'macOS custom attribute'; Path = 'deviceManagement/deviceCustomAttributeShellScripts'; Read = 'Expand' }
        @{ Category = 'WindowsUpdates'; Label = 'Feature update profile'; Path = 'deviceManagement/windowsFeatureUpdateProfiles' }
        @{ Category = 'WindowsUpdates'; Label = 'Quality update policy'; Path = 'deviceManagement/windowsQualityUpdatePolicies' }
        @{ Category = 'WindowsUpdates'; Label = 'Expedited update profile'; Path = 'deviceManagement/windowsQualityUpdateProfiles' }
        @{ Category = 'WindowsUpdates'; Label = 'Driver update profile'; Path = 'deviceManagement/windowsDriverUpdateProfiles' }
        @{ Category = 'Apps'; Label = 'App'; Path = 'deviceAppManagement/mobileApps' }
        @{ Category = 'Apps'; Label = 'App configuration (devices)'; Path = 'deviceAppManagement/mobileAppConfigurations' }
        @{ Category = 'Apps'; Label = 'App configuration (apps)'; Path = 'deviceAppManagement/targetedManagedAppConfigurations' }
        @{ Category = 'Apps'; Label = 'App protection (iOS)'; Path = 'deviceAppManagement/iosManagedAppProtections' }
        @{ Category = 'Apps'; Label = 'App protection (Android)'; Path = 'deviceAppManagement/androidManagedAppProtections' }
        @{ Category = 'Apps'; Label = 'App protection (Windows)'; Path = 'deviceAppManagement/windowsManagedAppProtections' }
        @{ Category = 'Enrollment'; Label = 'Enrollment configuration'; Path = 'deviceManagement/deviceEnrollmentConfigurations' }
        @{ Category = 'Enrollment'; Label = 'Autopilot profile'; Path = 'deviceManagement/windowsAutopilotDeploymentProfiles' }
        @{ Category = 'Enrollment'; Label = 'Terms and conditions'; Path = 'deviceManagement/termsAndConditions' }
        @{ Category = 'PolicySets'; Label = 'Policy set'; Path = 'deviceAppManagement/policySets' }
        @{ Category = 'Roles'; Label = 'Intune role assignment'; Path = 'deviceManagement/roleAssignments'; Read = 'Role' }
        @{ Category = 'Roles'; Label = 'Scope tag'; Path = 'deviceManagement/roleScopeTags' }
    )

    foreach ($row in $rows) {
        [pscustomobject]@{
            Category = $row.Category
            Label    = $row.Label
            Path     = $row.Path
            Read     = if ($row.ContainsKey('Read')) { $row.Read } else { 'Assignments' }
        }
    }
}

function Get-RequiredScope {
    <#
        .SYNOPSIS
            The scopes for the selected categories, each mapped to the broader
            scopes that also satisfy it, as Connect-GraphSession takes them.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Category
    )

    # Always: this one also names the assignment filters, whatever is searched.
    $scopes = [ordered]@{
        'DeviceManagementConfiguration.Read.All' = @('DeviceManagementConfiguration.ReadWrite.All')
        'GroupMember.Read.All'                   = @('GroupMember.ReadWrite.All', 'Group.Read.All', 'Group.ReadWrite.All',
            'Directory.Read.All', 'Directory.ReadWrite.All')
    }

    $ownScope = [ordered]@{
        Scripts    = 'DeviceManagementScripts'
        Apps       = 'DeviceManagementApps'
        Enrollment = 'DeviceManagementServiceConfig'
        Roles      = 'DeviceManagementRBAC'
    }
    foreach ($name in $ownScope.Keys) {
        if ($Category -contains $name) {
            $scopes["$($ownScope[$name]).Read.All"] = @("$($ownScope[$name]).ReadWrite.All")
        }
    }

    return $scopes
}

function Resolve-TargetGroup {
    <#
        .SYNOPSIS
            Finds the group by object ID or exact display name, and stops
            rather than choose between groups that share a name.

        .DESCRIPTION
            A group that no longer exists is not a failure when it is asked for
            by object ID: an assignment can outlive its group, and those are
            worth finding. The result then has Exists set to $false.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter()]
        [AllowEmptyString()]
        [string]$GroupName,

        [Parameter()]
        [AllowEmptyString()]
        [string]$GroupId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$BaseUri,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$MaximumAttempt = 5
    )

    $select = 'id,displayName,createdDateTime'

    if ($GroupId) {
        try {
            $group = Invoke-GraphRequestWithRetry -Uri "$BaseUri/groups/$GroupId`?`$select=$select" -MaximumAttempt $MaximumAttempt
        }
        catch {
            if ($_.Exception.Data.Contains('StatusCode') -and [int]$_.Exception.Data['StatusCode'] -eq 404) {
                Write-Warning "No group has the object ID '$GroupId'. Searching for it anyway, because an assignment can outlive its group."
                return [pscustomobject]@{ Id = $GroupId; DisplayName = ''; Exists = $false }
            }
            throw
        }

        return [pscustomobject]@{
            Id          = $GroupId
            DisplayName = [string](Get-PropertyValue -InputObject $group -Name 'displayName')
            Exists      = $true
        }
    }

    $name = $GroupName.Trim()
    $filter = [uri]::EscapeDataString("displayName eq '$($name.Replace("'", "''"))'")
    $found = Get-GraphCollection -Uri "$BaseUri/groups?`$filter=$filter&`$select=$select&`$top=999" -MaximumAttempt $MaximumAttempt

    if ($found.Count -eq 0) {
        throw "No group is named '$name'. The whole name has to match, though not its case. Check it, or use -GroupId."
    }

    if ($found.Count -gt 1) {
        $choices = foreach ($candidate in $found) {
            '{0} (created {1})' -f (Get-PropertyValue -InputObject $candidate -Name 'id'),
                (Get-PropertyValue -InputObject $candidate -Name 'createdDateTime')
        }
        throw "$($found.Count) groups are named '$name', so none was chosen. Rerun with -GroupId and one of: $($choices -join '; ')."
    }

    return [pscustomobject]@{
        Id          = [string](Get-PropertyValue -InputObject $found[0] -Name 'id')
        DisplayName = [string](Get-PropertyValue -InputObject $found[0] -Name 'displayName')
        Exists      = $true
    }
}

function Get-ParentGroup {
    <#
        .SYNOPSIS
            The groups a group is nested in, at any depth.

        .DESCRIPTION
            transitiveMemberOf also returns directory roles and administrative
            units, which cannot be assignment targets. They are dropped here
            rather than through the microsoft.graph.group cast, which needs
            advanced query parameters. A row with no type is kept: a parent
            searched for nothing costs one comparison, and one left out could
            hide an assignment.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$BaseUri,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$MaximumAttempt = 5
    )

    $parents = Get-GraphCollection -Uri "$BaseUri/groups/$GroupId/transitiveMemberOf?`$select=id,displayName" -MaximumAttempt $MaximumAttempt

    foreach ($parent in $parents) {
        $type = [string](Get-PropertyValue -InputObject $parent -Name '@odata.type')
        if ($type -and $type -ne '#microsoft.graph.group') { continue }

        [pscustomobject]@{
            Id          = [string](Get-PropertyValue -InputObject $parent -Name 'id')
            DisplayName = [string](Get-PropertyValue -InputObject $parent -Name 'displayName')
        }
    }
}

function Get-ObjectDisplayName {
    <#
        .SYNOPSIS
            An object's name: configurationPolicies call it name, everything
            else displayName.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        $InputObject
    )

    foreach ($property in 'displayName', 'name') {
        $value = [string](Get-PropertyValue -InputObject $InputObject -Name $property)
        if ($value) { return $value }
    }

    return '(no name)'
}

function ConvertTo-AssignmentEntry {
    <#
        .SYNOPSIS
            Reads which group one Graph assignment names, and how.

        .DESCRIPTION
            Returns nothing for a target that names no group by design, such as
            all devices. Any other target returns an entry. An entry with an
            empty GroupId is one this script cannot read: it may be the group,
            so the caller must not count it as a different one.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        $Assignment
    )

    $target = Get-PropertyValue -InputObject $Assignment -Name 'target'
    $type = ([string](Get-PropertyValue -InputObject $target -Name '@odata.type')).TrimStart('#') -replace '^microsoft\.graph\.', ''

    $namesNoGroup = @('allDevicesAssignmentTarget', 'allLicensedUsersAssignmentTarget', 'configurationManagerCollectionAssignmentTarget')
    if ($namesNoGroup -contains $type) { return }

    # scopeTagGroupAssignmentTarget holds its group in entraObjectId.
    $groupId = [string](Get-PropertyValue -InputObject $target -Name 'groupId')
    if (-not $groupId) { $groupId = [string](Get-PropertyValue -InputObject $target -Name 'entraObjectId') }

    $filterId = [string](Get-PropertyValue -InputObject $target -Name 'deviceAndAppManagementAssignmentFilterId')
    $filterMode = [string](Get-PropertyValue -InputObject $target -Name 'deviceAndAppManagementAssignmentFilterType')
    if (-not $filterId -or $filterId -eq [guid]::Empty.ToString() -or $filterMode -eq 'none') {
        $filterId = ''
        $filterMode = ''
    }

    [pscustomobject]@{
        GroupId    = $groupId
        Assignment = if ($type -eq 'exclusionGroupAssignmentTarget') { 'Exclude' } else { 'Include' }
        Intent     = [string](Get-PropertyValue -InputObject $Assignment -Name 'intent')
        FilterId   = $filterId
        FilterMode = $filterMode
        Source     = [string](Get-PropertyValue -InputObject $Assignment -Name 'source')
    }
}

function Get-RoleAssignmentEntry {
    <#
        .SYNOPSIS
            Reads the groups an Intune role assignment names: its members, and
            the groups it can manage.

        .DESCRIPTION
            Beta documents two lists of scope groups, scopeMembers and
            resourceScopes, so both are read. A response with no members list
            throws: it would otherwise pass for a role that names no group.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        $RoleAssignment
    )

    if ($null -eq $RoleAssignment -or $null -eq $RoleAssignment.PSObject.Properties['members']) {
        throw "The role assignment came back with no 'members' list."
    }

    $scopeIds = @(@(Get-PropertyValue -InputObject $RoleAssignment -Name 'resourceScopes') +
        @(Get-PropertyValue -InputObject $RoleAssignment -Name 'scopeMembers') |
            Where-Object { $_ } | Sort-Object -Unique)

    $named = [ordered]@{
        RoleMember = @($RoleAssignment.members)
        RoleScope  = $scopeIds
    }

    foreach ($kind in $named.Keys) {
        foreach ($groupId in $named[$kind]) {
            [pscustomobject]@{
                GroupId    = [string]$groupId
                Assignment = $kind
                Intent     = ''
                FilterId   = ''
                FilterMode = ''
                Source     = ''
            }
        }
    }
}

function Get-ObjectAssignmentEntry {
    <#
        .SYNOPSIS
            Reads one object's assignments the way its source needs, as
            entries. Throws when they cannot be read.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [pscustomobject]$Source,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ObjectId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$BaseUri,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$MaximumAttempt = 5
    )

    $objectUri = "$BaseUri/$($Source.Path)/$ObjectId"

    if ($Source.Read -eq 'Role') {
        $role = Invoke-GraphRequestWithRetry -Uri $objectUri -MaximumAttempt $MaximumAttempt
        Get-RoleAssignmentEntry -RoleAssignment $role
        return
    }

    if ($Source.Read -eq 'Expand') {
        $expandUri = '{0}?$expand=assignments' -f $objectUri
        $object = Invoke-GraphRequestWithRetry -Uri $expandUri -MaximumAttempt $MaximumAttempt

        # A response without the list would otherwise pass for an object
        # assigned to nothing.
        if ($null -eq $object -or $null -eq $object.PSObject.Properties['assignments']) {
            throw "GET $expandUri returned no 'assignments' list."
        }
        $assignments = $object.assignments
    }
    else {
        $assignments = Get-GraphCollection -Uri "$objectUri/assignments" -MaximumAttempt $MaximumAttempt
    }

    foreach ($assignment in $assignments) { ConvertTo-AssignmentEntry -Assignment $assignment }
}

function Find-SourceAssignment {
    <#
        .SYNOPSIS
            Searches one source. Returns the records it found, and a coverage
            row saying how much of the source could be read.

        .DESCRIPTION
            -Target maps each group ID being searched for to the group, with
            its Relationship. A failure never leaves this function: it becomes
            the coverage row, so that one source that cannot be read costs that
            source and not the run. The first HTTP 403 ends the source, since
            every later request would be refused for the same reason.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [pscustomobject]$Source,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [hashtable]$Target,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$BaseUri,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$MaximumAttempt = 5
    )

    $maximumNotes = 3
    $records = [System.Collections.Generic.List[object]]::new()
    $notes = [System.Collections.Generic.List[string]]::new()
    $objects = [System.Collections.Generic.List[object]]::new()
    $listed = $false
    $read = 0
    $failures = 0
    $unreadableTargets = 0

    try {
        $objects = Get-GraphCollection -Uri "$BaseUri/$($Source.Path)" -MaximumAttempt $MaximumAttempt
        $listed = $true
    }
    catch {
        $notes.Add($_.Exception.Message)
    }

    foreach ($object in $objects) {
        $objectId = [string](Get-PropertyValue -InputObject $object -Name 'id')
        $objectName = Get-ObjectDisplayName -InputObject $object

        try {
            $entries = @(Get-ObjectAssignmentEntry -Source $Source -ObjectId $objectId -BaseUri $BaseUri -MaximumAttempt $MaximumAttempt)
        }
        catch {
            $failures++
            if ($notes.Count -lt $maximumNotes) { $notes.Add("$objectName`: $($_.Exception.Message)") }

            if ($_.Exception.Data.Contains('StatusCode') -and [int]$_.Exception.Data['StatusCode'] -eq 403) { break }
            continue
        }

        $read++
        foreach ($entry in $entries) {
            if (-not $entry.GroupId) {
                $unreadableTargets++
                continue
            }
            if (-not $Target.ContainsKey($entry.GroupId)) { continue }

            $group = $Target[$entry.GroupId]
            $records.Add([pscustomobject]@{
                    Category        = $Source.Category
                    ObjectType      = $Source.Label
                    ObjectName      = $objectName
                    ObjectId        = $objectId
                    Assignment      = $entry.Assignment
                    Intent          = $entry.Intent
                    FilterName      = ''
                    FilterId        = $entry.FilterId
                    FilterMode      = $entry.FilterMode
                    Relationship    = $group.Relationship
                    AssignedGroup   = $group.DisplayName
                    AssignedGroupId = $group.Id
                    Source          = $entry.Source
                })
        }
    }

    $unread = $objects.Count - $read
    if ($unreadableTargets -gt 0) {
        $notes.Add("$unreadableTargets assignment(s) name a target this script cannot read.")
    }

    $status = 'Complete'
    if (-not $listed -or ($objects.Count -gt 0 -and $read -eq 0)) { $status = 'Failed' }
    elseif ($unread -gt 0 -or $unreadableTargets -gt 0) { $status = 'Partial' }

    return [pscustomobject]@{
        Coverage = [pscustomobject]@{
            Category = $Source.Category
            Source   = $Source.Label
            Status   = $status
            Objects  = $objects.Count
            Unread   = $unread
            Found    = $records.Count
            Detail   = $notes -join ' | '
        }
        Records  = $records
    }
}

function Resolve-AssignmentFilterName {
    <#
        .SYNOPSIS
            Fills in FilterName on the records that have a filter. A name is
            only a convenience: FilterId is already on the record, so a failure
            here warns and costs the name, not the run.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Record,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$BaseUri,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$MaximumAttempt = 5
    )

    $filtered = @($Record | Where-Object { $_.FilterId })
    if ($filtered.Count -eq 0) { return }

    try {
        $filters = Get-GraphCollection -Uri "$BaseUri/deviceManagement/assignmentFilters" -MaximumAttempt $MaximumAttempt
    }
    catch {
        Write-Warning "Assignment filter names could not be read, so the reports give FilterId only: $($_.Exception.Message)"
        return
    }

    $names = @{}
    foreach ($filter in $filters) {
        $names[[string](Get-PropertyValue -InputObject $filter -Name 'id')] = [string](Get-PropertyValue -InputObject $filter -Name 'displayName')
    }

    foreach ($item in $filtered) {
        if ($names.ContainsKey($item.FilterId)) { $item.FilterName = $names[$item.FilterId] }
    }
}

try {
    if (-not $GroupId -and [string]::IsNullOrWhiteSpace($GroupName)) {
        throw '-GroupName is blank. Give the group''s display name, or its object ID with -GroupId.'
    }

    #region Connect to Microsoft Graph
    $ConnectionOpenedHere = Connect-GraphSession -Scope (Get-RequiredScope -Category $Category) -TenantId $TenantId `
        -UseDeviceCode:$UseDeviceCode
    #endregion

    #region Find the group and the groups it is nested in
    $group = Resolve-TargetGroup -GroupName $GroupName -GroupId $GroupId -BaseUri $GraphBaseUri -MaximumAttempt $MaximumRetryCount
    $groupLabel = if ($group.DisplayName) { "'$($group.DisplayName)'" } else { "'$($group.Id)'" }

    $target = @{}
    $target[$group.Id] = [pscustomobject]@{ Id = $group.Id; DisplayName = $group.DisplayName; Relationship = 'Direct' }

    $parentCoverage = [pscustomobject]@{
        Category = 'Groups'
        Source   = 'Parent groups'
        Status   = 'Complete'
        Objects  = 0
        Unread   = 0
        Found    = 0
        Detail   = ''
    }

    if ($group.Exists) {
        try {
            $parents = @(Get-ParentGroup -GroupId $group.Id -BaseUri $GraphBaseUri -MaximumAttempt $MaximumRetryCount)
            $parentCoverage.Objects = $parents.Count
            foreach ($parent in $parents) {
                $target[$parent.Id] = [pscustomobject]@{ Id = $parent.Id; DisplayName = $parent.DisplayName; Relationship = 'Inherited' }
            }
            if ($parents.Count -gt 0) {
                Write-Information "Group $groupLabel is nested in: $(@($parents | ForEach-Object { $_.DisplayName }) -join ', ')."
            }
        }
        catch {
            $parentCoverage.Status = 'Failed'
            $parentCoverage.Detail = $_.Exception.Message
        }
    }
    else {
        $parentCoverage.Status = 'NotApplicable'
        $parentCoverage.Detail = 'The group does not exist, so it has no parents to read.'
    }
    #endregion

    #region Search
    $coverage = [System.Collections.Generic.List[object]]::new()
    $coverage.Add($parentCoverage)
    $records = [System.Collections.Generic.List[object]]::new()

    foreach ($source in Get-AssignmentSource) {
        if ($Category -notcontains $source.Category) {
            $coverage.Add([pscustomobject]@{
                    Category = $source.Category
                    Source   = $source.Label
                    Status   = 'NotSearched'
                    Objects  = 0
                    Unread   = 0
                    Found    = 0
                    Detail   = ''
                })
            continue
        }

        Write-Information "Searching: $($source.Label)"
        $result = Find-SourceAssignment -Source $source -Target $target -BaseUri $GraphBetaUri -MaximumAttempt $MaximumRetryCount
        $coverage.Add($result.Coverage)
        foreach ($record in $result.Records) { $records.Add($record) }
    }

    Resolve-AssignmentFilterName -Record @($records) -BaseUri $GraphBetaUri -MaximumAttempt $MaximumRetryCount
    #endregion

    #region Report
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $coverageFile = Join-Path -Path $OutputPath -ChildPath "GroupAssignment-$stamp-Coverage.csv"
    $coverage | Export-Csv -LiteralPath $coverageFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

    Write-Information ''
    Write-Information ('{0,-22} {1,-29} {2,-13} {3,7} {4,6}' -f 'Category', 'Source', 'Status', 'Objects', 'Found')
    foreach ($row in $coverage) {
        Write-Information ('{0,-22} {1,-29} {2,-13} {3,7} {4,6}' -f $row.Category, $row.Source, $row.Status, $row.Objects, $row.Found)
    }
    Write-Information ''

    $inherited = @($records | Where-Object { $_.Relationship -eq 'Inherited' }).Count
    Write-Information "Group $groupLabel`: $($records.Count - $inherited) direct and $inherited inherited assignment(s)."
    Write-Information "Coverage: $coverageFile"

    if ($records.Count -gt 0) {
        $reportFile = Join-Path -Path $OutputPath -ChildPath "GroupAssignment-$stamp.csv"
        $records | Export-Csv -LiteralPath $reportFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Information "Report: $reportFile"
    }
    else {
        Write-Information 'Finding nothing does not prove the group is unused: objects outside your Intune scope tags cannot be searched, and this script looks in Intune only. Its help lists what it leaves out.'
    }
    #endregion

    $records

    $incomplete = @($coverage | Where-Object { $_.Status -in @('Partial', 'Failed') })
    if ($incomplete.Count -gt 0) {
        $ExitCode = 2
        $names = @($incomplete | ForEach-Object { '{0} ({1})' -f $_.Source, $_.Status }) -join ', '
        Write-Warning "These results may be incomplete. Part of the search could not be read: $names. See Detail in $coverageFile."
    }
}
catch {
    # -Exception, not -ErrorRecord: Write-Error takes -Message with the first
    # and not with the second, and would fail here instead of reporting.
    # -ErrorAction Continue, or the preference set above would stop the script
    # at this line, before exit sets the code.
    Write-Error -Exception $_.Exception -Message "Script failed: $($_.Exception.Message)" -ErrorAction Continue
    exit 1
}
finally {
    if ($ConnectionOpenedHere -and (Get-MgContext)) {
        try {
            Disconnect-MgGraph -ErrorAction Stop | Out-Null
            Write-Verbose 'Disconnected from Microsoft Graph.'
        }
        catch {
            Write-Warning "Failed to disconnect from Microsoft Graph: $($_.Exception.Message)"
        }
    }
}

exit $ExitCode

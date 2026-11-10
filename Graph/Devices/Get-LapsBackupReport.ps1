# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/zenpachi-alt/endpoint-engineering

#Requires -Version 5.1

<#
.SYNOPSIS
    Reports, for every Windows device joined to Microsoft Entra ID, whether
    Entra ID holds a Windows LAPS backup of its local administrator password,
    and whether that password is overdue for rotation.

.DESCRIPTION
    Reads every device in Microsoft Entra ID and what Entra ID records about
    every Windows LAPS backup, joins them on the Entra device ID, and returns
    one object per Windows device that is Entra joined or hybrid joined, with
    a status:

      BackedUp  Entra ID holds a backup, and its next rotation is still
                ahead.
      Overdue   Entra ID holds a backup, and the date it was due to be
                rotated has passed. The device has not replaced the password
                when its policy said it would.
      NoBackup  Entra ID holds no backup for the device. The helpdesk cannot
                look up a local administrator password for it.

    The passwords themselves are never read. The script requests
    DeviceLocalCredential.ReadBasic.All, which cannot return them, and never
    asks for the credentials property, which is how a password is requested.
    Nothing is written to the tenant.

    What the report cannot tell:

    - Whether a LAPS policy reaches a device. NoBackup means either that no
      policy does, or that one does and the backup is failing.
    - Where else a password is kept. A hybrid joined device whose policy
      backs up to Windows Server Active Directory is healthy and shows
      NoBackup here, because Entra ID holds nothing for it. JoinType sets
      those devices apart.
    - Why a device is overdue. Most are switched off or away, and rotate
      when they return: compare DaysOverdue with DaysSinceLastSignIn.

    Registered devices, personal ones as a rule, cannot back up to Entra ID
    and are left out. So is every device Entra ID does not record as running
    Windows. The verbose stream counts the Windows devices left out, and the
    backups that belong to no device in the report.

    A warning is written when Entra ID holds no backup at all, which points
    at the tenant rather than at the devices: LAPS is switched on for a
    tenant in the Entra device settings.

.PARAMETER TenantId
    Tenant to connect to, as a GUID or a verified domain name. Optional: an
    existing Microsoft Graph session is reused when it matches, and omitting
    this connects to the signed-in user's home tenant.

.PARAMETER UseDeviceCode
    Authenticate with device code flow: the script prints a code and a URL to
    complete sign-in on any device.

.PARAMETER Status
    Keep only devices with one of these statuses.

.PARAMETER CsvPath
    Existing directory to write a timestamped CSV into. Objects are returned
    whether or not this is supplied.

.PARAMETER MaximumRetryCount
    Attempts per request, the first included, before giving up on a throttled
    or failing call.

.EXAMPLE
    .\Get-LapsBackupReport.ps1 -Status NoBackup | Format-Table DeviceName, JoinType, LastSignInDateTime

    The joined devices Entra ID holds no local administrator password for.

.EXAMPLE
    .\Get-LapsBackupReport.ps1 -Status Overdue | Sort-Object DaysOverdue -Descending | Format-Table DeviceName, DaysOverdue, DaysSinceLastSignIn

    The devices whose password is past its rotation date, longest first,
    beside the days since each last signed in.

.EXAMPLE
    .\Get-LapsBackupReport.ps1 -CsvPath C:\Reports -Verbose

    Every joined Windows device, written to a timestamped CSV, with a count
    of each status in the verbose stream.

.EXAMPLE
    .\Get-LapsBackupReport.ps1 | Group-Object Status -NoElement

    How many devices are in each status.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.0.0
    Last updated  : 2026-11-10

    PowerShell    : 5.1 or 7. No PowerShell 7 syntax is used.
    Graph scopes  : Device.Read.All
                    (Device.ReadWrite.All, Directory.Read.All and
                    Directory.ReadWrite.All accepted)
                    DeviceLocalCredential.ReadBasic.All
                    (DeviceLocalCredential.Read.All accepted when already
                    granted)
    Admin consent : Required, for both scopes.
    Licensing     : Microsoft Entra ID Free or higher. Backing up to Entra ID
                    needs no Intune licence.
    Modules       : Microsoft.Graph.Authentication 2.0.0 or later.
    Role required : An Entra role that may read LAPS details: Global Reader,
                    Security Reader, Security Administrator, Helpdesk
                    Administrator, Cloud Device Administrator or Intune
                    Administrator.

    Scoped roles  : An administrator whose role is scoped to administrative
                    units may not be shown every backup. Devices outside the
                    scope would show NoBackup. Run the report with a
                    tenant-wide role.

    Endpoint      : v1.0.

    Output        : The result names real devices. Treat the CSV as tenant
                    data: keep it out of this repository and off shared
                    locations.

.LINK
    https://learn.microsoft.com/graph/api/directory-list-devicelocalcredentials

.LINK
    https://learn.microsoft.com/graph/api/device-list

.LINK
    https://learn.microsoft.com/entra/identity/devices/howto-manage-local-admin-passwords
#>

[CmdletBinding()]
param (
    [Parameter()]
    [ValidatePattern('^([0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}|[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})$')]
    [string]$TenantId,

    [Parameter()]
    [switch]$UseDeviceCode,

    [Parameter()]
    [ValidateSet('BackedUp', 'Overdue', 'NoBackup')]
    [string[]]$Status,

    [Parameter()]
    [ValidateScript({
            if (Test-Path -LiteralPath $_ -PathType Container) { $true }
            else { throw "CsvPath '$_' does not exist or is not a directory." }
        })]
    [string]$CsvPath,

    [Parameter()]
    [ValidateRange(1, 10)]
    [int]$MaximumRetryCount = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Graph module 1.0.0 - canonical copy in Templates/Script-Template.ps1
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

# ReadBasic cannot return a password; Read.All can, and is accepted only
# because an administrator who already consented to it should not be asked
# again.
$RequiredScopes = [ordered]@{
    'Device.Read.All'                     = @('Device.ReadWrite.All', 'Directory.Read.All', 'Directory.ReadWrite.All')
    'DeviceLocalCredential.ReadBasic.All' = @('DeviceLocalCredential.Read.All')
}

$GraphBaseUri = 'https://graph.microsoft.com/v1.0'
$ConnectionOpenedHere = $false

#region Graph helpers 1.0.0 - canonical copy in Templates/Script-Template.ps1
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

function ConvertTo-JoinKind {
    <#
        .SYNOPSIS
            Names how a device is joined, from the trustType Entra ID records
            for it.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        $TrustType
    )

    switch ([string]$TrustType) {
        'AzureAd' { return 'EntraJoined' }
        'ServerAd' { return 'HybridJoined' }
        'Workplace' { return 'Registered' }
        default { return 'Unknown' }
    }
}

function Get-LapsReportData {
    <#
        .SYNOPSIS
            Reads every Entra device and what Entra ID records about every
            LAPS backup, without the password, and returns both lists.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$BaseUri,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$MaximumAttempt = 5
    )

    # Every device is read, and the joined Windows ones are picked out
    # locally, so the devices left out can be counted.
    $select = 'id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,accountEnabled,approximateLastSignInDateTime'
    $devices = Get-GraphCollection -Uri "$BaseUri/devices?`$select=$select&`$top=999" -MaximumAttempt $MaximumAttempt

    # No query options, and never $select=credentials: that is how a password
    # is asked for, and the scope cannot return one. The list returns id,
    # deviceName, lastBackupDateTime and refreshDateTime.
    try {
        $backups = Get-GraphCollection -Uri "$BaseUri/directory/deviceLocalCredentials" -MaximumAttempt $MaximumAttempt
    }
    catch {
        $statusCode = 0
        if ($_.Exception.Data.Contains('StatusCode')) { $statusCode = [int]$_.Exception.Data['StatusCode'] }

        if ($statusCode -eq 403) {
            throw ('Listing LAPS backups was refused (HTTP 403). DeviceLocalCredential.ReadBasic.All is granted, so the ' +
                'signed-in account also needs an Entra role that may read LAPS details: Global Reader, Security Reader, ' +
                "Security Administrator, Helpdesk Administrator, Cloud Device Administrator or Intune Administrator. $($_.Exception.Message)")
        }
        throw
    }

    return [pscustomobject]@{
        Devices = $devices
        Backups = $backups
    }
}

function ConvertTo-LapsReport {
    <#
        .SYNOPSIS
            Joins the joined Windows devices to LAPS backups on the Entra
            device ID and returns one record per device. Reads no state, so
            every combination can be tested without a tenant.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Device,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Backup,

        # The moment a rotation date is compared with. A parameter so that a
        # test can hold it still.
        [Parameter()]
        [datetime]$Now = [datetime]::UtcNow
    )

    $Now = $Now.ToUniversalTime()

    # Backups by Entra device ID, compared without regard to case. Should
    # Entra ID list two for one device, the one backed up last is kept.
    $backupByDevice = @{}
    foreach ($item in $Backup) {
        $deviceId = [string](Get-PropertyValue -InputObject $item -Name 'id')
        if (-not $deviceId) { continue }

        $entry = [pscustomobject]@{
            LastBackup   = ConvertTo-UtcDateTime -Value (Get-PropertyValue -InputObject $item -Name 'lastBackupDateTime')
            NextRotation = ConvertTo-UtcDateTime -Value (Get-PropertyValue -InputObject $item -Name 'refreshDateTime')
        }

        $lookup = $deviceId.ToLowerInvariant()
        if ($backupByDevice.ContainsKey($lookup)) {
            $kept = $backupByDevice[$lookup].LastBackup
            if ($null -ne $kept -and ($null -eq $entry.LastBackup -or $entry.LastBackup -le $kept)) { continue }
        }
        $backupByDevice[$lookup] = $entry
    }

    foreach ($item in $Device) {
        if ([string](Get-PropertyValue -InputObject $item -Name 'operatingSystem') -ne 'Windows') { continue }

        # Only a joined device can back up to Entra ID.
        $joinType = ConvertTo-JoinKind -TrustType (Get-PropertyValue -InputObject $item -Name 'trustType')
        if ($joinType -ne 'EntraJoined' -and $joinType -ne 'HybridJoined') { continue }

        $entraId = [string](Get-PropertyValue -InputObject $item -Name 'deviceId')
        $held = $null
        if ($entraId -and $backupByDevice.ContainsKey($entraId.ToLowerInvariant())) {
            $held = $backupByDevice[$entraId.ToLowerInvariant()]
        }

        $lastBackup = $null
        $nextRotation = $null
        if ($null -ne $held) {
            $lastBackup = $held.LastBackup
            $nextRotation = $held.NextRotation
        }

        # A backup with no rotation date is held all the same, and nothing
        # says it is late.
        $status = if ($null -eq $held) { 'NoBackup' }
        elseif ($null -ne $nextRotation -and $nextRotation -lt $Now) { 'Overdue' }
        else { 'BackedUp' }

        $daysOverdue = $null
        if ($status -eq 'Overdue') { $daysOverdue = [int][math]::Floor(($Now - $nextRotation).TotalDays) }

        $lastSignIn = ConvertTo-UtcDateTime -Value (Get-PropertyValue -InputObject $item -Name 'approximateLastSignInDateTime')
        $daysSinceLastSignIn = $null
        if ($null -ne $lastSignIn) { $daysSinceLastSignIn = [int][math]::Floor(($Now - $lastSignIn).TotalDays) }

        [pscustomobject]@{
            DeviceName             = Get-PropertyValue -InputObject $item -Name 'displayName'
            Status                 = $status
            JoinType               = $joinType
            LastBackupDateTime     = $lastBackup
            NextRotationDateTime   = $nextRotation
            DaysOverdue            = $daysOverdue
            LastSignInDateTime     = $lastSignIn
            DaysSinceLastSignIn    = $daysSinceLastSignIn
            AccountEnabled         = Get-PropertyValue -InputObject $item -Name 'accountEnabled'
            OperatingSystemVersion = Get-PropertyValue -InputObject $item -Name 'operatingSystemVersion'
            EntraDeviceId          = $entraId
            ObjectId               = Get-PropertyValue -InputObject $item -Name 'id'
        }
    }
}

try {
    #region Connect to Microsoft Graph
    $ConnectionOpenedHere = Connect-GraphSession -Scope $RequiredScopes -TenantId $TenantId `
        -UseDeviceCode:$UseDeviceCode
    #endregion

    #region Read and join
    $data = Get-LapsReportData -BaseUri $GraphBaseUri -MaximumAttempt $MaximumRetryCount
    Write-Verbose "Read $($data.Devices.Count) device(s) and $($data.Backups.Count) LAPS backup(s)."

    $records = @(ConvertTo-LapsReport -Device @($data.Devices) -Backup @($data.Backups))
    Write-Verbose "$($records.Count) joined Windows device(s)."

    $windowsCount = @($data.Devices | Where-Object { [string](Get-PropertyValue -InputObject $_ -Name 'operatingSystem') -eq 'Windows' }).Count
    if ($windowsCount -gt $records.Count) {
        Write-Verbose ("$($windowsCount - $records.Count) Windows device(s) are registered, or of a join type Entra ID does not name, " +
            'and are not reported: only a joined device can back up to Entra ID.')
    }

    $reported = @{}
    foreach ($record in $records) { if ($record.EntraDeviceId) { $reported[$record.EntraDeviceId.ToLowerInvariant()] = $true } }
    $unmatched = @($data.Backups | Where-Object {
            $backupDevice = [string](Get-PropertyValue -InputObject $_ -Name 'id')
            -not $backupDevice -or -not $reported.ContainsKey($backupDevice.ToLowerInvariant())
        })
    if ($unmatched.Count -gt 0) {
        Write-Verbose "$($unmatched.Count) backup(s) belong to no device in the report, and are not reported."
    }

    foreach ($group in @($records | Group-Object -Property Status | Sort-Object -Property Name)) {
        Write-Verbose "$($group.Name): $($group.Count)"
    }

    if ($records.Count -gt 0 -and $data.Backups.Count -eq 0) {
        Write-Warning ('Entra ID holds no LAPS backup for any device. Check that LAPS is enabled in the Entra device settings ' +
            'of the tenant, and that a LAPS policy backs up to Microsoft Entra ID.')
    }
    #endregion

    #region Filter
    $results = $records
    if ($Status) {
        $results = @($results | Where-Object { $Status -contains $_.Status })
    }

    if ($results.Count -eq 0) {
        Write-Warning 'No devices matched. Check -Status, or whether the tenant has joined Windows devices.'
    }
    #endregion

    #region Export
    if ($CsvPath) {
        $file = Join-Path -Path $CsvPath -ChildPath ('LapsBackupReport-{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        $results | Export-Csv -LiteralPath $file -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Verbose "Wrote $($results.Count) row(s) to '$file'."
    }
    #endregion

    $results
}
catch {
    # -Exception, not -ErrorRecord: Write-Error takes -Message with the first
    # and not with the second, and would fail here instead of reporting.
    # -ErrorAction Continue, or the preference set above would stop the script
    # at this line, before exit sets the code.
    Write-Error -Exception $_.Exception -Message "Report failed: $($_.Exception.Message)" -ErrorAction Continue
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

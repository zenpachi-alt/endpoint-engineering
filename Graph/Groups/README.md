# Groups

Group membership changes made from a workstation against the tenant, and
finding where a group is used before changing it.

| Script | Purpose |
| --- | --- |
| `Add-GroupDeviceMember.ps1` | Resolves a list of device names to Entra device object IDs, filtered by join type and recent activity, and adds them to a group or writes the portal's bulk import CSV. |
| `Get-GroupAssignment.ps1` | Finds everything in Intune assigned to a group, by name or object ID, directly or through a parent group, and reports what it could and could not read. Read-only. |

## Add-GroupDeviceMember.ps1

The usual starting point is a list of host names from a spreadsheet, a
ticket or an on-premises query. Group membership needs each device's Entra
**object ID**, and a name doesn't always identify a single device. Hybrid join,
re-imaging and personal registrations all leave several device records with
the same name. This script looks each name up, sets aside the records that
fail the filters, and reports exactly what happened to every name.

### Prerequisites

| Requirement | Detail |
| --- | --- |
| PowerShell | 5.1 or 7 |
| Module | `Microsoft.Graph.Authentication` 2.0.0 or later |
| Graph scopes | `Device.Read.All`. With `-GroupId`, also `GroupMember.ReadWrite.All`, or only `GroupMember.Read.All` with `-WhatIf`. Broader scopes that are already granted are accepted; see `.NOTES` in the script. |
| Admin consent | Required for every scope, once per tenant |
| Licensing | Microsoft Entra ID Free. No Intune licence is needed. |
| Role | Reading devices: any member user, unless default user permissions are restricted. Adding: Groups Administrator, Intune Administrator (security groups only), User Administrator, Directory Writers, or an owner of the group. A role-assignable group also needs Privileged Role Administrator. |

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

### Examples

```powershell
# Hybrid joined devices active in the last 30 days: report and import CSV only
.\Add-GroupDeviceMember.ps1 -Path .\servers.txt -TrustType ServerAd -ActiveWithinDays 30

# The same names from a CSV column, checked against a group without changing it
.\Add-GroupDeviceMember.ps1 -Path .\devices.csv -ColumnName Hostname `
    -GroupId '<GroupId>' -TrustType ServerAd -ActiveWithinDays 30 -WhatIf

# Add them, after one confirmation, with the files written to C:\Reports
.\Add-GroupDeviceMember.ps1 -Path .\servers.txt -GroupId '<GroupId>' `
    -TrustType ServerAd -ActiveWithinDays 30 -OutputPath C:\Reports

# The names that did not resolve to exactly one device, and why
.\Add-GroupDeviceMember.ps1 -DeviceName 'PC01', 'PC02' |
    Where-Object Status -ne 'Matched' | Format-Table InputName, Status, Reason
```

For an unattended run, add `-Confirm:$false`. Without it, the script asks
once before adding the batch.

### Input

`-Path` takes a text file with one name per line, or a CSV file. A CSV is read
from `-ColumnName`, or from its only column. `-DeviceName` takes names
directly.

Names are trimmed and compared without regard to case. A fully qualified name
is looked up by its host name, so `pc01.contoso.com` finds `pc01`. A name
that contains a space is kept whole. Duplicate names are collapsed and counted
in a warning.

### Filters

| Parameter | Keeps |
| --- | --- |
| `-TrustType` | `ServerAd` (Microsoft Entra hybrid joined), `AzureAd` (Microsoft Entra joined), `Workplace` (Microsoft Entra registered). Several may be given. |
| `-ActiveWithinDays` | Devices whose activity timestamp, `approximateLastSignInDateTime`, is no older than this. A device with no timestamp is excluded. |
| `-IncludeDisabled` | Disabled devices as well. They are excluded by default because a disabled device cannot authenticate to Entra ID. |

**"Last sync" here means Entra activity**, not an Intune check-in or an
Entra Connect sync. Entra ID refreshes the timestamp only once it is 14 days
old, give or take 5, so a window shorter than 21 days excludes devices that are
in use. The script warns when you ask for one.

The filters are applied locally, after the lookup, so an excluded device can
be reported along with the reason. Only the name lookup runs on the service:
`displayName in (...)`, 15 names per request.

### Status

| Status | Meaning |
| --- | --- |
| `Matched` | Exactly one device record by that name passed the filters. `ObjectId` is the one to use. |
| `NotFound` | No device record has that name. |
| `Excluded` | Records have that name, and none passed. `Reason` gives what each one failed. |
| `Ambiguous` | More than one record passed. None is chosen: narrow the filters, or clean up the stale duplicates. `CandidateObjectIds` lists them. |

A `Matched` record whose name also belongs to records that failed the filters
says so in `Reason`. That is usually the stale half of a re-imaged or
dual-registered device.

`ObjectId` is the directory object ID that group membership uses. `DeviceId`
is the device's own registration ID. The two are easy to confuse, and only the
first works for membership.

### Adding to a group

With `-GroupId`, the group is checked before any device is looked up. The
script refuses a group whose membership cannot take devices added by hand:

- a group with dynamic membership
- a Microsoft 365 group (only security groups can hold devices)
- a distribution list or mail-enabled security group
- a group synced from on-premises Active Directory

Devices already in the group are skipped and reported as `AlreadyMember`.
The rest are added one request at a time, because a request that adds several
devices fails completely if any one of them is refused. The first HTTP 403
stops the batch: every later request would be refused for the same reason.

**Adding a device to a group can start deployments to it immediately.**
Whatever is assigned to the group, whether apps, configuration profiles,
scripts or remediations, applies to the new members at their next check-in.
Run with `-WhatIf` first.

| Membership | Meaning |
| --- | --- |
| `Added` | The device was added. |
| `AlreadyMember` | The device was already a direct member. |
| `WouldAdd` | Under `-WhatIf`, or with the confirmation declined, this device would have been added. |
| `Failed` | The request was refused; `MembershipDetail` says why. |
| `NotAttempted` | An earlier 403 stopped the batch. |

The script exits `1` when any device is `Failed` or `NotAttempted`, after
returning every record and writing the report. Names that did not resolve do
not change the exit code. They are data to act on, not a failed run. The code
is the same in a session, as `$LASTEXITCODE`, and from `pwsh -File`.

### Output files

Both files are written to `-OutputPath`, which defaults to the temp directory.

- `GroupDeviceMember-<timestamp>.csv` is every record, in input order.
- `GroupDeviceMember-<timestamp>-Import.csv` holds the `Matched` object IDs
  in the format the Microsoft Entra admin center expects under **Groups** >
  the group > **Members** > **Bulk operations** > **Import members**. It
  starts with the template's exact header and has no version row. Current
  members are left out, because the import would fail on them. The file is
  written unless the script added the devices itself. The admin center asks
  for at least two rows, and the script warns when there is only one.

Records are also returned on the pipeline, so they can be filtered and
formatted without reopening a file.

### How it is tested

`Add-GroupDeviceMember.Tests.ps1` loads the script's functions and runs the
body of its main block against a stand-in tenant held in memory. The stand-in
answers the device lookup by parsing the filter the script sends, so a filter
that asks for the wrong names fails. The tests cover:

- input cleaning and CSV columns
- batching and quote escaping in the lookup
- every status, filter, and filter combination, including the boundary day
- every group the script refuses
- the add requests, `-WhatIf`, a retried add that had already landed, and the
  403 stop
- both files and the exit path
- the script started with `-File` in a child process, for its exit code and
  its message; skipped where `Microsoft.Graph.Authentication` is not installed

The tests run under Windows PowerShell 5.1 and PowerShell 7. What they cannot
show is a real tenant's answers.

### Reference

- [Add members to a group](https://learn.microsoft.com/graph/api/group-post-members)
- [device resource type](https://learn.microsoft.com/graph/api/resources/device)
- [Bulk add group members](https://learn.microsoft.com/entra/identity/users/groups-bulk-import-members)
- [Manage stale devices: the activity timestamp](https://learn.microsoft.com/entra/identity/devices/manage-stale-devices)

## Get-GroupAssignment.ps1

A group can be assigned in many places, and Intune keeps each assignment on the
policy, app or script it belongs to. Neither the admin center nor Graph can be
asked what a group is assigned, so before changing a group there is no quick way
to see what the change would touch. This script reads every object in the
sources below, reads each object's assignments, and lists the ones that name the
group. It never writes to the tenant.

### Prerequisites

| Requirement | Detail |
| --- | --- |
| PowerShell | 5.1 or 7 |
| Module | `Microsoft.Graph.Authentication` 2.0.0 or later |
| Graph scopes | Always `DeviceManagementConfiguration.Read.All` and `GroupMember.Read.All`. By `-Category`, see below. The `ReadWrite` equivalents are accepted where already granted, as are `Group.Read.All` and `Directory.Read.All` for the group. |
| Admin consent | Required for every scope, once per tenant |
| Licensing | Microsoft Intune Plan 1 |
| Role | Any Intune role that can read these objects; read-only operator roles are enough. Reading groups: any member user, unless default user permissions are restricted. |

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

### Examples

```powershell
# Everything assigned to the group, or to a group it is nested in
.\Get-GroupAssignment.ps1 -GroupName 'Pilot devices'

# By object ID, signing in with a device code, with the files written to C:\Reports
.\Get-GroupAssignment.ps1 -GroupId '<GroupId>' -UseDeviceCode -OutputPath C:\Reports

# Apps and scripts only
.\Get-GroupAssignment.ps1 -GroupName 'Pilot devices' -Category Apps, Scripts

# Where the group is excluded, which is where removing it widens a deployment
.\Get-GroupAssignment.ps1 -GroupName 'Pilot devices' |
    Where-Object Assignment -eq 'Exclude' | Format-Table ObjectType, ObjectName, AssignedGroup
```

### Finding the group

`-GroupName` is the whole display name, compared without regard to case. Graph
does not keep display names unique, so a name that belongs to more than one
group stops the run and lists their object IDs. None is chosen: rerun with
`-GroupId`.

An object ID that no group has is searched for anyway, with a warning, because
an assignment can outlive the group it names.

The groups the group is nested in are searched as well, since their assignments
reach its members. Those records have `Relationship` `Inherited` and name the
parent in `AssignedGroup`.

### Records

One record per assignment, returned on the pipeline and written to the report.

| Column | Meaning |
| --- | --- |
| `Category`, `ObjectType` | The `-Category` the object belongs to, and what kind of object it is. |
| `ObjectName`, `ObjectId` | The policy, app or script. |
| `Assignment` | What the group does there; see below. |
| `Intent` | For apps: `required`, `available`, `uninstall` or `availableWithoutEnrollment`. |
| `FilterName`, `FilterId`, `FilterMode` | The assignment filter, and whether it includes or excludes. |
| `Relationship` | `Direct`, or `Inherited` through a parent group. |
| `AssignedGroup`, `AssignedGroupId` | The group the assignment names: the group searched for, or its parent. |
| `Source` | `policySets` when a policy set delivers the assignment. Change it there, not on the object. Blank where Graph does not say. |

| Assignment | Meaning |
| --- | --- |
| `Include` | The object is deployed to the group. |
| `Exclude` | The group is held out of the object. **Removing it from an exclusion widens the deployment**, the opposite of what removing a group usually does. |
| `RoleMember` | The group's members hold the Intune role. |
| `RoleScope` | The Intune role can manage the group's members. |

### Coverage

An empty result can be acted on, so what was searched matters as much as what
was found. Every run writes a coverage report with one row per source and prints
it, and a source that could not be read is never treated as holding nothing.

| Status | Meaning |
| --- | --- |
| `Complete` | Every object in the source was read. |
| `Partial` | Part of the source could not be read, or an assignment names a target the script cannot read. `Detail` says which. |
| `Failed` | The source could not be read at all. |
| `NotSearched` | `-Category` left the source out. |
| `NotApplicable` | Only for parent groups, of a group that does not exist. |

The first HTTP 403 ends a source, because every later request would be refused
for the same reason. A target of a type the script does not know is not assumed
to be a different group: it marks the source `Partial`.

| Code | Meaning |
| --- | --- |
| `0` | Every selected source was read. Finding nothing is a result, not a failure. |
| `1` | The script failed before searching: sign-in, or a group name that is unknown or ambiguous. |
| `2` | The records are returned, but part of the search could not be read, so they may be incomplete. |

The code is the same in a session, as `$LASTEXITCODE`, and from `pwsh -File`.

### Sources

| `-Category` | Searches | Scope of its own |
| --- | --- | --- |
| `ConfigurationProfiles` | Device configuration profiles, settings catalog policies, administrative templates, security baseline intents | None |
| `CompliancePolicies` | Compliance policies | None |
| `Scripts` | Remediations, Windows platform scripts, macOS shell scripts and custom attributes | `DeviceManagementScripts.Read.All` |
| `WindowsUpdates` | Feature, quality, expedited and driver update policies | None |
| `Apps` | Apps, app configuration for devices and for apps, app protection for iOS, Android and Windows | `DeviceManagementApps.Read.All` |
| `Enrollment` | Enrollment configurations, Autopilot profiles, terms and conditions | `DeviceManagementServiceConfig.Read.All` |
| `PolicySets` | Policy sets | None |
| `Roles` | Intune role assignments, scope tags | `DeviceManagementRBAC.Read.All` |

Every category is searched by default. One left out asks for no scope of its
own, which is the way to run where a scope has not been consented to yet.

The run takes about one request per object, plus one per source, so a large
tenant takes minutes. Apps are read one at a time because Microsoft has
deprecated `$expand=assignments` on the app list. The macOS script collections
are read through `$expand` on each object, because the documented assignments
path of `deviceShellScripts` answers HTTP 400.

Intune is read on beta. Most of these collections exist nowhere else. A change
in the beta contract shows up as a `Failed` or `Partial` source, not as a missing
record.

### What it does not show

**It shows where a group is used in Intune, not that a group is safe to delete.**

- Anything outside Intune: Conditional Access, Entra roles, enterprise apps,
  group-based licensing, access packages, Exchange, SharePoint, Teams.
- Within Intune: Windows Autopatch groups, which have no documented Graph API
  (the policies and Entra groups they create are searched like any other),
  Windows 365 provisioning policies, branding profiles, eSIM activation pools,
  managed e-books, iOS app provisioning profiles, S mode supplemental policies,
  and the device group of an enrollment time grouping policy.
- Objects outside the signed-in account's Intune scope tags. Graph does not
  return them and gives no sign that they exist, so use an account that sees
  every object before trusting an empty result.

### Output files

Both files are written to `-OutputPath`, which defaults to the temp directory.
They name real policies and groups, so keep them out of this repository.

- `GroupAssignment-<timestamp>.csv` is every record. It is not written when
  nothing was found.
- `GroupAssignment-<timestamp>-Coverage.csv` is every source and its status. It
  is written on every run that reaches the search.

### How it is tested

`Get-GroupAssignment.Tests.ps1` loads the script's functions and runs the body
of its main block against a stand-in tenant held in memory, keyed by URI, so a
request for the wrong path fails. The tests cover:

- finding a group by name and by ID, a shared name, a quote in a name, and a
  group that no longer exists
- parent groups, including the directory roles and administrative units that
  come back with them
- every kind of target: include, exclude, all devices, a group held in
  `entraObjectId`, a target type the script does not know, and no target at all
- role assignments, and each source's way of being read
- every way a read can fail, each of which must show in the coverage report and
  never pass for nothing assigned
- filter names, the scopes each category asks for, and the exit code
- the script started with `-File` in a child process, for its exit code and its
  message; skipped where `Microsoft.Graph.Authentication` is not installed

The tests run under Windows PowerShell 5.1 and PowerShell 7. What they cannot
show is a real tenant's answers.

### Reference

- [Intune in Microsoft Graph](https://learn.microsoft.com/graph/api/resources/intune-graph-overview)
- [List group transitive memberOf](https://learn.microsoft.com/graph/api/group-list-transitivememberof)
- [Assignment targets](https://learn.microsoft.com/graph/api/resources/intune-shared-deviceandappmanagementassignmenttarget)
- [Intune role assignments](https://learn.microsoft.com/graph/api/resources/intune-rbac-deviceandappmanagementroleassignment)
- [mobileApp: listing with `$expand=assignments` is deprecated](https://learn.microsoft.com/graph/api/resources/intune-apps-mobileapp)

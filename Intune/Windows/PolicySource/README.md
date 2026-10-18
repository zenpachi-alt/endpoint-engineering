# PolicySource

Where does this policy setting come from? On a device managed by both Group
Policy and Intune, often by two different teams, nothing on the device answers
that directly. `Get-PolicySource.ps1` does: for every policy setting, which GPO
or MDM setting sets it, what value each one wants, and which value Windows is
actually using.

| File | Role |
| --- | --- |
| `Get-PolicySource.ps1` | Reads every local source of policy and returns one row per setting, with a verdict. |
| `Get-PolicySource.Tests.ps1` | Pester tests: each reader against a registry tree built under `HKEY_CURRENT_USER`, the ADMX reader against fixture files and the device's own `PolicyDefinitions`, each verdict, and the script run as a file. |

## Why it is needed

Intune writes many settings to the same `HKLM\SOFTWARE\Policies` keys Group
Policy writes. A message such as "a Group Policy setting prevents this" names
the mechanism, not the team: the value may well have come from Intune. A
BitLocker prompt about removable drives is a common example. The Intune setting
`BitLocker/RemovableDrivesRequireEncryption` and the GPO setting *Deny write
access to removable drives not protected by BitLocker* write the same registry
value.

When both sides set the same thing, one of three things happens:

- **Without `MDMWinsOverGP`**, both apply. Which value Windows uses depends on
  which wrote last, and Microsoft gives no guarantee which that is.
- **With `ControlPolicyConflict/MDMWinsOverGP` on**, Windows stops applying the
  GPO setting. The GPO still holds it, but the RSoP data, `rsop.msc` and
  `gpresult`'s main list no longer show it. Only `gpresult`'s
  *Setting controlled by a different authority* section does, and that needs a
  domain controller. The GP team sees nothing wrong, and the setting comes back
  as soon as the Intune policy is removed.
- **Neither side knows about the other.** Intune's reports compare Intune
  policies with each other, and Group Policy analytics reads GPO backups, not
  what a device received.

The device is the only place both sides meet, so the script runs there.

## Get-PolicySource.ps1

Run it in an elevated Windows PowerShell on the device:

```powershell
# Everything, the settings that need a decision first
.\Get-PolicySource.ps1

# BitLocker, wherever it comes from (FVE is BitLocker's policy key)
.\Get-PolicySource.ps1 -Filter '*FVE*', '*BitLocker*'

# Only what both sides claim, where one of them loses
.\Get-PolicySource.ps1 -Verdict Conflict, OverriddenByMdm, NotApplied

# Every column, with the note that explains each verdict
.\Get-PolicySource.ps1 -Filter '*WindowsUpdate*' | Format-List

# Remote Desktop settings by their Group Policy names, with what each side wants
.\Get-PolicySource.ps1 -Filter '*Terminal Services*' |
    Format-Table -Property Verdict, PolicyDisplayName, GpValue, MdmRegistryValue, LiveValue -Wrap

# A file for the other team
.\Get-PolicySource.ps1 | Export-Csv -Path .\PolicySource.csv -NoTypeInformation
```

`-Filter` takes wildcards and tries each one against the setting, the registry
path, the MDM setting, the GPO name, the ADMX policy and its name in Group
Policy. `-IncludeWindowsInternal` adds what Windows provisions for itself (see
below).

### Verdicts

Rows come back in this order:

| Verdict | Meaning |
| --- | --- |
| `Conflict` | Group Policy and an MDM both apply it, with different values. For an ADMX-backed MDM setting, the MDM's value is the one its state means (`MdmRegistryValue`). The note says whose value the registry holds. |
| `OverriddenByMdm` | A GPO sets it, but Group Policy did not apply it because an MDM sets it too. The note says whether the GPO's value differs from the one in effect. |
| `NotApplied` | A GPO sets it, Group Policy did not apply it, and no active MDM setting explains why. When a leftover is listed for it, the note says so; otherwise check the Group Policy operational log. |
| `Both` | Both set it. Intune sends ADMX-backed settings as a state (`Enabled`, `Disabled`, with any data), not as the registry value, and this setting's ADMX definition was not found, so the note compares the GPO's value with the registry instead and says why the definition is missing. |
| `Agree` | Both set it, to the same value. |
| `GpOnly` | Group Policy only: a registry policy setting, a Preferences item, or a wireless profile. |
| `MdmOnly` | Intune or another MDM only. |
| `Leftover` | PolicyManager still lists an MDM setting for it, but no enrollment holds a value, so no MDM applies it now. That is what remains when a policy is removed from the device, and it can also show briefly while an MDM re-applies its policies: run again after a sync to tell which. The registry value, if any, stayed behind. |
| `Unclaimed` | A value under `HKLM\SOFTWARE\Policies` that no source claims: a script, an app, another management tool, or a Windows default. |

A leftover is never taken for the source of a value. It still matters: with
`MDMWinsOverGP` on, an MDM setting PolicyManager still lists can keep the
matching GPO setting from applying, although nothing applies the MDM's.

### Columns

| Column | Holds |
| --- | --- |
| `Verdict` | One of the verdicts above. |
| `Setting` | The MDM setting name where there is one (`Area/Policy`), otherwise the registry key and value. |
| `LiveValue` | The value in the registry now. |
| `GpValue`, `Gpo` | The value Group Policy sets and the winning GPO. For `OverriddenByMdm` and `NotApplied`, the GPO that holds the setting. |
| `OverriddenGpo` | GPOs that set the same value but lost on precedence. |
| `GpSource` | `Registry policy`, `Preferences`, `Wireless profile`, or `GPO, not applied`. |
| `MdmSetting`, `MdmValue` | The MDM setting and its value. An ADMX state is shown as `Enabled: id=value; ...`. |
| `MdmSource`, `MdmSourceKind` | Who set it: `Intune`, another MDM's provider name, `Windows`, or `None` for a leftover. |
| `MatchedBy` | How the row was tied to the MDM setting: `Value` when PolicyManager maps the setting to exactly this value, `Admx` when the setting's ADMX definition writes this value, `Key` when the setting's ADMX definition was not found and it writes somewhere under this key. A match by key is weaker evidence. |
| `RegistryPath` | The registry value, from `HKLM`. |
| `Note` | Why the verdict is what it is, and anything that does not add up. A value written after Group Policy or the MDM is one example. |
| `AdmxPolicy` | The ADMX policy that writes this value, as `File.admx: PolicyName` or `ingested Prefix: PolicyName`. For an MDM setting, its own; otherwise every policy that writes the value, up to three. |
| `PolicyDisplayName` | That policy's name in the Group Policy editor, from the ADML in the device's language, or English. Empty when the ADMX file has no ADML, as with ingested files. |
| `MdmRegistryValue` | The value an ADMX-backed MDM setting's state means here, worked out from its ADMX definition: a value, `not set` when the state removes it, or `0 or not set` where the ADMX leaves Windows the choice. |

Only the first seven columns show by default; `Format-List` or `Select-Object *`
shows the rest. The last three were added in 1.2, after the others, so an
export from 1.1 and one from 1.2 line up column for column.

### How it decides

Everything is read locally. Nothing contacts a domain controller or the
internet, so it works off the corporate network.

| Source | Where | Gives |
| --- | --- | --- |
| MDM | `HKLM\SOFTWARE\Microsoft\PolicyManager` | Each setting's value, the winning enrollment, and its registry mapping |
| Group Policy | RSoP, `root\rsop\computer` | The applied registry settings, the winning GPO, the GPOs that lost |
| GPO cache | `%windir%\System32\GroupPolicy\DataStore` | Each applied GPO's own `Registry.pol`, including settings that were not applied |
| Preferences | `%ProgramData%\Microsoft\Group Policy\History` | Group Policy Preferences registry items |
| ADMX | `%windir%\PolicyDefinitions`, and the copies Windows keeps of ADMX files an MDM ingested | What each policy writes to the registry, and its name in Group Policy |
| Registry | The value itself | What Windows reads now |

PolicyManager records, for each setting, the registry value it writes
(`RegKeyPathRedirect`, `RegValueNameRedirect`) and the Group Policy value
`MDMWinsOverGP` blocks (`GPBlockingRegKeyPath`, `GPBlockingRegValueName`), in
`default\<Area>\<Policy>` for settings built into Windows and in `AdmxDefault`
for ingested ADMX. That mapping is what puts an MDM setting and a GPO setting
on the same row. The setting's value is in `current\device\<Area>`, or, for one
stored at its registry location, in the winning enrollment's own store under
`providers`.

A GPO setting in the cache that RSoP does not show was not applied. When an MDM
setting writes the same value, directly or through its ADMX definition, that is
`OverriddenByMdm`, and so is a value under the key of an ADMX-backed setting
whose definition was not found.

A setting with no winning enrollment and no value is a leftover. The `knobs`
area is always Windows' own, whatever its record says, and the copies of list
items PolicyManager keeps as `<Policy>_<Element>_ListSet` are not settings.
An MDM setting that writes one value and blocks Group Policy at another, such as
`System/AllowTelemetry`, gets one row, the one with Group Policy in it. Its note
says where the MDM's own value is.

`gpresult` is not used. It needs a domain controller and stalls for minutes
without one, and the RSoP data and the cache together hold what it would add.

### ADMX-backed settings

Intune sends an ADMX-backed setting as a state, such as `<enabled/>` with
`<data id="..." value="..."/>` for each option, and Windows writes the
registry values the setting's ADMX definition gives for that state. The script
reads the same definitions and works out those values, so it can compare them
with Group Policy's and with the registry.

It finds the ADMX policy behind an MDM setting in this order, and takes a match
only when there is exactly one:

1. `ADMX_<File>/<Policy>` names the file and the policy.
2. An ingested area, `<App>~<SettingType>~<category path>`, names the policy by
   its category path in the ingested files.
3. The registry value PolicyManager maps the setting to, when one policy writes
   it.
4. A setting PolicyManager maps to a key only: the policy under that key that
   offers every element id in the setting's data.

The state then becomes values: `enabledValue` (1 when the ADMX gives none) and
the `enabledList`, and each element from its data. A `decimal` gives its number,
a `boolean` its `trueValue` or `falseValue`, an `enum` the value of the chosen
item plus that item's `valueList`, `text` the string, `multiText` its lines,
and a `list` its name and value pairs. `<disabled/>` removes the element values
and writes `disabledValue` and the `disabledList`. Where the ADMX gives no
`disabledValue` or `falseValue`, Windows may write 0 or remove the value, so
both count as the state's value.

The setting is then tied to each value its policy writes (`MatchedBy` `Admx`),
and compared like any other value. A value under the same key that the policy
does not write is not credited to it, and its note names the settings that were
ruled out. A setting whose policy is not found is compared as before: the GPO's
value against the registry, and a match by key, with a note saying why.

Ingested files: Microsoft documents that Windows keeps a copy on disk but not
where. The script looks for ADMX content, whatever the file is called, under
`%ProgramData%\Microsoft\PolicyManager*` and in PolicyManager's `AdmxInstalled`
key, and the log says how many it found.

Reading every ADMX file and its ADML takes a few seconds in Windows PowerShell
5.1. They are read on every run, not cached, so the result always matches the
files on the device.

### What it leaves out

- **Windows' own provisioning.** PolicyManager holds hundreds of settings that
  Windows sets for itself through enrollments of type 1, mostly power and
  processor tuning. They are not anyone's policy, so they are left out unless
  `-IncludeWindowsInternal` is given.
- **RSoP entries that are not settings**: entries without a value name, which
  create keys, and `**` entries, which delete values or keys.
- **User settings.** Only computer settings are read.
- **Security settings**: password and lockout policy, user rights, audit. They
  are applied by a separate engine, not through the registry.
- **ADMX files that are not on the device.** The central store is on SYSVOL and
  needs a domain controller, so only the device's own files are read. A setting
  whose definition is missing (some `ADMX_*` areas name files Windows no longer
  ships) is compared and matched by key as before. Its `MdmSetting` lists every
  such setting that writes under the key, and notes name up to three.

`Unclaimed` is only looked for under `HKLM\SOFTWARE\Policies`. A value a script
writes anywhere else is not reported.

### Prerequisites

| Requirement | Detail |
| --- | --- |
| PowerShell | Windows PowerShell 5.1. It runs on the device, where PowerShell 7 cannot be assumed. |
| Modules | None |
| Context | Elevated. The RSoP data and the GPO cache are readable by administrators only. |
| Network | Not required |
| Graph scopes | None. Nothing leaves the device. |
| Licensing | None to run. It reads what Group Policy and an MDM have applied. |
| Role | Local administrator on the device |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The sources were read. Includes a run where no setting matches the filter. |
| `1` | Not elevated, or the MDM or Group Policy data could not be read. The reason is on stderr and in the log. |

This is a technician tool, not a remediation, so the `0`/`1`/`2` detection
contract in [`Templates/Remediation/README.md`](../../../Templates/Remediation/README.md)
does not apply.

If RSoP logging is turned off (policy *Turn off Resultant Set of Policy
logging*), the script stops with `1` rather than report every Group Policy
setting as missing. If the GPO cache or the Preferences history cannot be read,
it warns and carries on without `OverriddenByMdm`, `NotApplied` or Preferences.
If the ADMX files cannot be read, or one of them cannot, it warns, names them,
and compares the settings they define as without ADMX definitions.

The log, `%ProgramData%\EndpointEngineering\Logs\Get-PolicySource.log`, holds
counts and timings, not values. For ADMX it records how many files were read,
how many ADMX-backed settings had their policy found, counted by how or by why
not, and how often the value a state means matched the registry where only the
MDM writes it.

### The output is organisation data

Rows hold GPO names, policy values, and sometimes identifiers set as policy
values. OneDrive's tenant allow list, for example, is a list of tenant IDs.
Before the output leaves the organisation, in a ticket, a vendor case or a chat,
run it through [`Invoke-TextScrub.ps1`](../../../Standalone/Invoke-TextScrub.ps1)
and read it.

## Verification status

The tests cover each source reader, the `Registry.pol` parser, the ADMX reader
and translation against fixture files, every verdict, and the filters. One test
reads the device's own `PolicyDefinitions` and translates a Remote Desktop
state through it. They run under Windows PowerShell 5.1 and PowerShell 7. The
script itself is run as a file: unelevated it stops at the elevation check with
`1`, and elevated, as in CI, it must finish with `0`.

Version 1.1 has been run on a hybrid-joined, Intune-enrolled device, and the
verdicts held.

Not yet exercised: the verdicts against a deliberately conflicting GPO and
Intune policy, a device with `MDMWinsOverGP` off, and the ADMX translation
(1.2) on an enrolled device, including where Windows keeps ingested files.

## Reference

- [Policy CSP - ControlPolicyConflict](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-controlpolicyconflict)
- [Policies in Policy CSP supported by Group Policy](https://learn.microsoft.com/windows/client-management/mdm/policies-in-policy-csp-supported-by-group-policy)
- [Understanding ADMX-backed policies](https://learn.microsoft.com/windows/client-management/understanding-admx-backed-policies)
- [Registry policy file format](https://learn.microsoft.com/previous-versions/windows/desktop/policy/registry-policy-file-format)

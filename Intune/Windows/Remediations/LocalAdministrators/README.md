# LocalAdministrators

Detection-only script package that reports the members of the local
Administrators group on each device, and lists the devices where a member is
neither built in nor on your allow-list.

It removes nobody. Membership is enforced with Intune's own policy, *Endpoint
security > Account protection > Local user group membership*. This package
answers the two questions that policy does not: what is in the group before you
enforce it, and what has drifted since.

| File | Role |
| --- | --- |
| `Test-LocalAdministrators.ps1` | Detection only. Reads the group and the device's own SID, sorts each member, and reports one line. Changes nothing. |
| `Test-LocalAdministrators.Tests.ps1` | Pester tests: what each member is taken for, which are expected, and the exit code and output line for each situation. Not deployed. |

## How it decides

The group is found by its SID, `S-1-5-32-544`, so the script works in every
display language. Each member is sorted by its SID alone, which needs no network
and no directory:

| Kind | What it is | Expected |
| --- | --- | --- |
| `BuiltInAdministrator` | The device's own account with RID 500, whatever it is named. | Always. |
| `LocalAccount` | Another account of this device. | When its name is in `AllowedLocalAccountName`. |
| `EntraPrincipal` | A Microsoft Entra user, group or role (`S-1-12-1-...`). | When its SID is in `AllowedSid`. |
| `DomainAdmins` | The Domain Admins group of an Active Directory domain (RID 512). | Always: Windows adds it when a device joins a domain. |
| `DomainPrincipal` | Any other domain account or group. | When its SID is in `AllowedSid`. |
| `Other` | Anything else, such as a well-known group. | When its SID is in `AllowedSid`. |

Three choices behind that:

- **The verdict follows the SID, not the name.** A name is trusted only for an
  account of the device itself, because a local account has a different SID on
  every device. A domain or Entra account that happens to carry an allowed name
  is still not allowed.
- **A missing name is not a missing account.** An Entra role or group has no
  name on a device, and a domain account has none while no domain controller
  answers. Such a member is reported by its SID, and sorted like any other.
- **`Get-LocalGroupMember` is not used.** It fails when the group holds a member
  it cannot resolve, and an Entra joined device always holds some. The group is
  read through ADSI, which returns such a member as its SID.

## Two modes

A SID cannot say whether an Entra member is a user, a group or a role. The two
roles Windows adds to the group on Entra join, Global Administrator and
Microsoft Entra Joined Device Local Administrator, have SIDs that differ in
every tenant. So an allow-list is needed, and the package helps you build it:

| Mode | Behaviour |
| --- | --- |
| `Inventory` | Lists every member, those not allowed first, and always exits `0`. This is how the script ships. |
| `Detect` | Exits `1` when a member is neither built in nor allowed. |

1. **Deploy it as it is.** Export the device status report and read the output
   column. The SIDs that appear on every Entra joined device are your tenant's
   two roles.
2. **Set the defaults in your own copy.** Intune runs the script without
   parameters, so the mode and the allow-list are the parameter defaults at the
   top of the script:

   ```powershell
   [string]$Mode = 'Detect',

   [string[]]$AllowedSid = @('<RoleSid1>', '<RoleSid2>'),

   [string[]]$AllowedLocalAccountName = @('<LapsAccountName>'),
   ```

3. **Try the list on one device** before deploying it, by passing the same
   values as parameters:

   ```powershell
   .\Test-LocalAdministrators.ps1 -Mode Detect -AllowedSid '<RoleSid1>', '<RoleSid2>' -Verbose
   ```

4. **Deploy your copy.** From then on, a device with any other member is listed
   under *With issues*.

**Keep your copy out of any public repository.** The SIDs identify your tenant.
This repository holds only the version with an empty allow-list.

A mistake in the defaults fails the check instead of passing quietly: an entry
of `AllowedSid` that is not a SID, or holds a number too large for one, exits
`2` and names the entry.

## Output

One line, starting with a token for filtering an export:

| Token | Exit | Meaning |
| --- | --- | --- |
| `Inventory` | `0` | Inventory mode. Every member, those not allowed first. |
| `Expected` | `0` | Detect mode. Every member is built in or allowed. |
| `Unexpected` | `1` | Detect mode. The members that are not allowed. |

A check that could not be completed exits `2`, never `1`, and writes no line.

Each member is written as its name, SID and kind, or as its SID where it has no
name on the device:

```text
Unexpected: 1 of 3 member(s) are not allowed: <DeviceName>\<AccountName> (S-1-5-21-<MachineSid>-1001, LocalAccount).
```

Intune keeps 2,048 characters of output, so a crowded group is cut short there.
The log has every member with its verdict:
`%ProgramData%\EndpointEngineering\Logs\Test-LocalAdministrators.log`.

The output and the log name real accounts and SIDs. Treat an export as tenant
data.

## Intune settings

| Setting | Value |
| --- | --- |
| Detection script file | `Test-LocalAdministrators.ps1`, your own copy once the defaults are set |
| Remediation script file | None |
| Run this script using the logged-on credentials | No |
| Enforce script signature check | No, unless the script is signed |
| Run script in 64-bit PowerShell | Either. Nothing the script reads is redirected. |
| Schedule | Daily. The check takes a second or two. |

With no remediation script, exit `1` starts nothing: it only puts the device
under *With issues* in the device status report.

## Limitations

- **Not for a fleet where users are administrators by design.** Every such
  device would be listed. The package suits a fleet that aims for standard
  users.
- **It cannot tell an Entra role from an Entra user or group.** Only the
  allow-list says which Entra SIDs belong.
- **Domain Admins is always expected**, for any domain. A device that carries
  the Domain Admins group of a domain you do not expect is not flagged for it.
- **Members of a member are not expanded.** A group in the allow-list is
  trusted with whoever is in it.
- **Reading the group has run on one workgroup device so far.** The sorting is
  tested for every kind of member, but the read through ADSI has not yet been
  run on an Entra joined or hybrid joined device, where the group holds SIDs
  with no name. Run it by hand on one such device before deploying it widely.

## Tests

`Test-LocalAdministrators.Tests.ps1` checks the rules directly, then runs the
script as the Intune management extension does, in Windows PowerShell 5.1 with
`-File`, with the two functions that touch the device replaced by stand-ins. It
covers every kind of member, both allow-lists, both modes, the 2,048-character
limit, the log, and the rule that a failed check exits `2`, never `1`:

```powershell
Invoke-Pester -Path .\Intune\Windows\Remediations\LocalAdministrators -Output Detailed
```

No test reads the group of the machine it runs on, and every SID in the tests
is made up.

## Licensing and permissions

Remediations require Intune plus Windows Enterprise E3/E5, Windows Education
A3/A5, or Windows VDA per user. Creating and assigning the package needs the
Intune *Device configurations* permissions. On the device, the script only
reads, so SYSTEM or any user can run it.

## Reference

- [Manage the local administrators group on Microsoft Entra joined devices](https://learn.microsoft.com/entra/identity/devices/assign-local-admin)
- [Account protection policy for endpoint security in Intune](https://learn.microsoft.com/intune/device-configuration/endpoint-security/account-protection)
- [Policy CSP - LocalUsersAndGroups](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-localusersandgroups)
- [Well-known SIDs](https://learn.microsoft.com/windows/win32/secauthz/well-known-sids)

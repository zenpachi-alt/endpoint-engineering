# Security policy

These scripts run with real privileges: as SYSTEM on managed devices, and with
Microsoft Graph permissions against a tenant. A flaw in one is a flaw wherever
it has been deployed, so please report it privately first.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:
[**Report a vulnerability**](https://github.com/zenpachi-alt/endpoint-engineering/security/advisories/new),
also reachable from the repository's **Security** tab. It needs a GitHub
account. The report is visible only to you and to me until an advisory is
published.

Please do not open a public issue or pull request for a vulnerability. That
discloses it to everyone at once, before anyone who has copied the script has a
fixed version to move to.

## What to report privately

- A script that can be made to do more than its documentation says with the
  privileges it runs under. Example: a way for a standard user to make a script
  running as SYSTEM write, delete or run something of their choosing.
- A script that writes a secret to a log, to its output or to disk: a token, a
  recovery key, a credential.
- A real identifier or secret committed to this repository, in a file or in its
  history: a tenant ID, an address, a hostname, a key.
- A weakness in the CI workflow that would let a pull request run with more
  access than it should.

## What does not belong here

- **Vulnerabilities in Microsoft products**: Windows, Intune, Entra ID,
  Microsoft Graph or the Graph PowerShell SDK. Report those to the
  [Microsoft Security Response Center](https://msrc.microsoft.com/).
- **A script doing what its documentation says**, with rights the person
  running it already holds. A script that deletes devices deletes devices.
- **Ordinary bugs**: a wrong result, a crash, a missed case. Open a public
  issue.
- **A gap in the identifier and secret scanner**, shown with made-up values.
  That is an ordinary bug too. If the example is a real value already in this
  repository, it is the third item of the list above.

If you are not sure which side something falls on, report it privately. Nothing
is lost by that.

## What to include

- The script's name and the `Version` under `.NOTES` in its help. A copy keeps
  that number wherever it travels, so it identifies exactly what you tested.
- How it was run: delivered by Intune as SYSTEM, by a technician on the device,
  or from a workstation against a tenant. The PowerShell version, and the
  Windows build where it matters.
- The steps to reproduce it, and what an attacker gains.
- Output with identifiers removed. The report is private, but it does not need
  your tenant ID, device names or user names to be useful.
  [`Invoke-TextScrub.ps1`](Standalone/README.md#invoke-textscrubps1) replaces
  them with consistent placeholders.

Test only against tenants and devices you are responsible for.

## Supported versions

Only the current version of each script on `main` is supported. There are no
releases and no maintained older versions: a fix raises the script's `Version`
on `main`, and that is the version to take.

## What to expect

This is a personal project, maintained in my own time, so the commitments are
modest and meant to be kept:

- I aim to acknowledge a report within a week.
- I will tell you whether I can reproduce it, and what I intend to do about it.
- A confirmed vulnerability is fixed on `main`, and a security advisory is
  published naming the script and the versions affected.
- You are credited in the advisory unless you would rather not be.

There is no bug bounty.

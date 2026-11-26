# entra-signin-triage

Answers "why can't this user sign in?" in one command, instead of six portal blades.

Read-only. Makes no changes to anything.

```powershell
.\Invoke-SignInTriage.ps1 -UserPrincipalName jane.doe@contoso.com
```

```
Account
-------
  [ ok ] Account is enabled. Jane Doe, created 2021-03-14.
  [ -- ] Synced from on-prem AD. Account state and password policy are owned on-prem, not here.
  [warn] Password last changed 94 days ago. If the tenant expires passwords, this is a candidate.

Authentication methods
----------------------
  [ ok ] Registered: microsoftAuthenticator, password, phone.

Sign-ins, last 24 hours
-----------------------
  [fail] 6 of 9 sign-ins failed.
  [fail] AADSTS500121 x6: MFA not completed, user did not approve or it timed out
  [ -- ]    apps: Office 365 Exchange Online, Outlook Mobile
  [ -- ]    next: Most common real MFA failure. Ask what they saw. Push not arriving is
            usually the phone, not the tenant.

Summary
-------
  [fail] 2 blocking issue(s). Start at the top of this list.
```

## Why this exists

The question arrives several times a week and the answer is always in a different place. Is the account enabled. Has the password expired. Does the user have an MFA method registered at all. Which conditional access policy caught them. Is the device compliant. What did the sign-in log actually say, and what does `AADSTS53003` mean.

Each of those is a different blade in a different portal, so in practice a Tier 1 analyst checks two of them, finds nothing, and escalates. This checks all six in about four seconds and translates the error code into what to do next.

It is deliberately a triage tool, not a fixer. It tells you where to look. You decide what to change.

## What it checks

| Section | What it tells you |
|---|---|
| Account | Enabled or disabled, created date, on-prem synced, guest, password age, last successful sign-in |
| Authentication methods | What is registered, and flags password-only or a single second factor |
| Licences | Assigned SKUs, flags unlicensed |
| Sign-ins | Recent failures grouped by error code, each translated to plain English with a next step |
| Conditional access | Enabled policies that appear to target this user, and their grant controls |
| Intune devices | Compliance state per device, flags stale sync |

Roughly twenty-five sign-in error codes are translated, chosen because they are the ones that actually turn up on a service desk rather than because they are in the documentation.

## Requirements

- PowerShell 5.1 or later
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/powershell/microsoftgraph/installation): `Install-Module Microsoft.Graph -Scope CurrentUser`
- Entra ID P1 or better for the sign-in log and last-sign-in sections. Without it, run with `-SkipSignInLogs` and the rest still works.

Delegated scopes requested, all read-only:

```
User.Read.All
Directory.Read.All
UserAuthenticationMethod.Read.All
AuditLog.Read.All
Policy.Read.All
DeviceManagementManagedDevices.Read.All
```

If a scope has not been consented, that section reports that it could not be read and the rest of the report still runs. One missing permission should not cost you the whole thing.

## Usage

```powershell
# Standard run
.\Invoke-SignInTriage.ps1 -UserPrincipalName jane.doe@contoso.com

# Three days of sign-in history
.\Invoke-SignInTriage.ps1 -UserPrincipalName jane.doe@contoso.com -LookbackHours 72

# JSON, for pasting into a ticket or piping somewhere
.\Invoke-SignInTriage.ps1 -UserPrincipalName jane.doe@contoso.com -AsJson

# Tenant without Entra ID P1
.\Invoke-SignInTriage.ps1 -UserPrincipalName jane.doe@contoso.com -SkipSignInLogs

# Keep a copy
.\Invoke-SignInTriage.ps1 -UserPrincipalName jane.doe@contoso.com -OutputPath .\jane.json
```

## What it does not do

Worth being clear about, because a triage tool that overstates itself is worse than no tool.

- **It does not change anything.** No unlocking, no password resets, no re-enabling, no policy edits. Read-only by design, which is also why it is safe to hand to Tier 1.
- **Conditional access scoping is an approximation.** It matches user and group include and exclude rules. It ignores app, platform, location, client and risk conditions, so a policy listed as targeting the user may not actually fire, and the report says so. Use the portal What If tool before you conclude that CA is or is not the cause.
- **It does not read risk state.** Risky user and risky sign-in detail needs Entra ID P2 and is not covered yet.
- **It will not find a problem that is not an identity problem.** When everything comes back healthy, that is the useful answer: stop looking at the account and go look at the client, the application or the network.

## Run metrics

Each run appends a line to `logs/triage-runs.csv`: timestamp, duration, Graph calls, and counts of failures and warnings found. No user data, no UPNs, nothing identifying.

It is there so that the question "what did this actually save" has an answer backed by data instead of a guess.

## Licence

MIT. See [LICENSE](LICENSE).

## Author

Ahmed Abdoulaye, Calgary. Desktop and endpoint support, Microsoft identity, PowerShell.

Built independently. Nothing in this repository comes from or is specific to any employer's environment.

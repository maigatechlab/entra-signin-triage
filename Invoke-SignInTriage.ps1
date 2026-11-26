#Requires -Version 5.1
<#
.SYNOPSIS
    Answers "why can't this user sign in?" in one command. Read-only.

.DESCRIPTION
    Collects the handful of facts a service desk actually needs when a user
    reports a sign-in problem, from the places they normally live in separate
    portal blades:

        account state        enabled, deleted, on-prem synced
        password             last changed, age
        MFA                  methods registered, or none
        licences             assigned SKUs
        sign-in logs         recent failures, with the error code in plain English
        conditional access   enabled policies that could apply
        devices              Intune compliance state for the user's devices

    Makes no changes of any kind. Every Graph scope requested is read-only.

.PARAMETER UserPrincipalName
    The user to look at. UPN, not display name.

.PARAMETER LookbackHours
    How far back to read sign-in logs. Default 24.

.PARAMETER MaxSignIns
    How many recent sign-in records to pull. Default 20.

.PARAMETER AsJson
    Emit the result as JSON instead of a formatted console report. Useful if
    you are piping this into a ticket.

.PARAMETER OutputPath
    Write the report to a file as well as the console.

.PARAMETER SkipSignInLogs
    Skip the sign-in log section. Sign-in log access needs Entra ID P1 or
    better, so use this in tenants without it.

.EXAMPLE
    .\Invoke-SignInTriage.ps1 -UserPrincipalName jane.doe@contoso.com

.EXAMPLE
    .\Invoke-SignInTriage.ps1 -UserPrincipalName jane.doe@contoso.com -LookbackHours 72 -AsJson

.NOTES
    Author : Ahmed Abdoulaye / Maiga Tech Lab
    Licence: MIT
    Needs  : Microsoft.Graph PowerShell SDK
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')]
    [string]$UserPrincipalName,

    [ValidateRange(1, 720)]
    [int]$LookbackHours = 24,

    [ValidateRange(1, 200)]
    [int]$MaxSignIns = 20,

    [switch]$AsJson,

    [string]$OutputPath,

    [switch]$SkipSignInLogs
)

$ErrorActionPreference = 'Stop'
$script:StartedAt = Get-Date
$script:GraphCalls = 0

# ---------------------------------------------------------------------------
# Sign-in error codes worth translating. Not exhaustive: these are the ones
# that actually turn up on a service desk, with what to do about each.
# ---------------------------------------------------------------------------
$script:ErrorCodes = @{
    50053   = @{ Meaning = 'Account locked by smart lockout, too many bad password attempts'; Action = 'Wait out the lockout or reset. Check whether the attempts came from the user or from somewhere else.' }
    50055   = @{ Meaning = 'Password expired'; Action = 'User needs to change it. Self-service if SSPR is enabled.' }
    50057   = @{ Meaning = 'Account is disabled'; Action = 'Re-enable, or find out why it was disabled before you do.' }
    50058   = @{ Meaning = 'Silent sign-in failed, no session'; Action = 'Usually benign. The client then prompts interactively.' }
    50074   = @{ Meaning = 'Strong authentication required, MFA not satisfied'; Action = 'Check the user completed the prompt. See 500121 below.' }
    50076   = @{ Meaning = 'MFA required by conditional access'; Action = 'Expected. Confirm the user has a usable MFA method registered.' }
    50079   = @{ Meaning = 'User must enrol in MFA'; Action = 'No method registered yet. Walk them through registration.' }
    50105   = @{ Meaning = 'User not assigned to a role for this application'; Action = 'Assign the app, or the group that grants it.' }
    50126   = @{ Meaning = 'Wrong username or password'; Action = 'Ordinary bad password, unless you are seeing many across users.' }
    50133   = @{ Meaning = 'Session invalid, password changed or expired'; Action = 'Sign out and back in.' }
    50140   = @{ Meaning = 'Interrupted by the Keep me signed in prompt'; Action = 'Benign.' }
    50158   = @{ Meaning = 'External security challenge not satisfied'; Action = 'Third-party MFA or an external provider did not complete.' }
    51004   = @{ Meaning = 'Account does not exist in the directory'; Action = 'Check the UPN. Often a typo or a stale alias.' }
    53000   = @{ Meaning = 'Device is not compliant'; Action = 'Intune compliance. See the device section of this report.' }
    53001   = @{ Meaning = 'Device is not domain joined or registered'; Action = 'Register or hybrid join the device.' }
    53002   = @{ Meaning = 'App protection policy required'; Action = 'User needs an approved client app, often Outlook mobile rather than the native mail app.' }
    53003   = @{ Meaning = 'Blocked by conditional access'; Action = 'Read the CA section. The named policy is in the raw log entry.' }
    53004   = @{ Meaning = 'User must complete MFA proof-up'; Action = 'Registration required before access is granted.' }
    65001   = @{ Meaning = 'User or admin has not consented to the application'; Action = 'Grant consent.' }
    90094   = @{ Meaning = 'Admin consent required'; Action = 'An admin has to approve the app.' }
    500121  = @{ Meaning = 'MFA not completed, user did not approve or it timed out'; Action = 'Most common real MFA failure. Ask what they saw. Push not arriving is usually the phone, not the tenant.' }
    530032  = @{ Meaning = 'Blocked by a security policy'; Action = 'Security defaults or a CA policy. Check both.' }
    700016  = @{ Meaning = 'Application not found in the directory'; Action = 'Wrong tenant or the app registration is gone.' }
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Section {
    param([string]$Title)
    if ($AsJson) { return }
    Write-Host ''
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ('-' * $Title.Length) -ForegroundColor DarkCyan
}

function Write-Finding {
    param(
        [ValidateSet('ok', 'warn', 'fail', 'info')]
        [string]$Level,
        [string]$Text
    )
    $script:Findings += [pscustomobject]@{ Level = $Level; Text = $Text }
    if ($AsJson) { return }
    $map = @{ ok = @('  [ ok ] ', 'Green'); warn = @('  [warn] ', 'Yellow'); fail = @('  [fail] ', 'Red'); info = @('  [ -- ] ', 'Gray') }
    Write-Host $map[$Level][0] -ForegroundColor $map[$Level][1] -NoNewline
    Write-Host $Text
}

function Invoke-Safely {
    <# Runs a Graph lookup and turns a failure into a finding instead of a crash.
       One missing permission should not cost you the rest of the report. #>
    param(
        [Parameter(Mandatory)][scriptblock]$Script,
        [Parameter(Mandatory)][string]$Label
    )
    try {
        $script:GraphCalls++
        & $Script
    }
    catch {
        Write-Finding -Level 'warn' -Text "$Label could not be read: $($_.Exception.Message)"
        $null
    }
}

$script:Findings = @()
$report = [ordered]@{}

# ---------------------------------------------------------------------------
# Connect
# ---------------------------------------------------------------------------
$scopes = @(
    'User.Read.All'
    'Directory.Read.All'
    'UserAuthenticationMethod.Read.All'
    'AuditLog.Read.All'
    'Policy.Read.All'
    'DeviceManagementManagedDevices.Read.All'
)

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw 'Microsoft.Graph PowerShell SDK not found. Install-Module Microsoft.Graph -Scope CurrentUser'
}

$context = Get-MgContext -ErrorAction SilentlyContinue
if (-not $context) {
    Write-Verbose 'Connecting to Microsoft Graph'
    Connect-MgGraph -Scopes $scopes -NoWelcome | Out-Null
    $context = Get-MgContext
}

$missing = $scopes | Where-Object { $_ -notin $context.Scopes }
if ($missing) {
    Write-Warning "Consented scopes are missing: $($missing -join ', '). Some sections will be incomplete."
}

$report['tenant']    = $context.TenantId
$report['queriedBy'] = $context.Account
$report['user']      = $UserPrincipalName
$report['runAt']     = (Get-Date).ToString('o')

# ---------------------------------------------------------------------------
# 1. The account
# ---------------------------------------------------------------------------
Write-Section 'Account'

$props = @(
    'id', 'displayName', 'userPrincipalName', 'accountEnabled', 'createdDateTime'
    'lastPasswordChangeDateTime', 'onPremisesSyncEnabled', 'usageLocation'
    'userType', 'signInActivity'
)

$user = Invoke-Safely -Label 'User object' -Script {
    Get-MgUser -UserId $UserPrincipalName -Property $props -ErrorAction Stop
}

if (-not $user) {
    Write-Finding -Level 'fail' -Text "No user found for $UserPrincipalName. Check the UPN, and check whether the account was deleted."
    $report['findings'] = $script:Findings
    if ($AsJson) { $report | ConvertTo-Json -Depth 6 }
    return
}

$report['displayName'] = $user.DisplayName
$report['objectId']    = $user.Id

if ($user.AccountEnabled) {
    Write-Finding -Level 'ok' -Text "Account is enabled. $($user.DisplayName), created $($user.CreatedDateTime.ToString('yyyy-MM-dd'))."
}
else {
    Write-Finding -Level 'fail' -Text 'Account is DISABLED. This alone explains the failure. Find out why before re-enabling.'
}

if ($user.UserType -eq 'Guest') {
    Write-Finding -Level 'info' -Text 'This is a guest account. B2B sign-in follows the home tenant, so check there too.'
}

if ($user.OnPremisesSyncEnabled) {
    Write-Finding -Level 'info' -Text 'Synced from on-prem AD. Account state and password policy are owned on-prem, not here.'
}

if ($user.LastPasswordChangeDateTime) {
    $age = [int]((Get-Date) - $user.LastPasswordChangeDateTime).TotalDays
    $report['passwordAgeDays'] = $age
    if ($age -ge 90) {
        Write-Finding -Level 'warn' -Text "Password last changed $age days ago. If the tenant expires passwords, this is a candidate."
    }
    else {
        Write-Finding -Level 'ok' -Text "Password last changed $age days ago."
    }
}

if ($user.SignInActivity.LastSignInDateTime) {
    Write-Finding -Level 'info' -Text "Last successful interactive sign-in: $($user.SignInActivity.LastSignInDateTime)."
}
else {
    Write-Finding -Level 'info' -Text 'No successful interactive sign-in on record. Needs Entra ID P1 to be populated.'
}

# ---------------------------------------------------------------------------
# 2. MFA methods
# ---------------------------------------------------------------------------
Write-Section 'Authentication methods'

$methods = Invoke-Safely -Label 'Authentication methods' -Script {
    Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction Stop
}

if ($null -ne $methods) {
    # The SDK returns the method type in the OData type of each object.
    $names = $methods | ForEach-Object {
        ($_.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', '' -replace 'AuthenticationMethod', '')
    } | Where-Object { $_ } | Sort-Object -Unique

    $report['authMethods'] = @($names)
    $strong = $names | Where-Object { $_ -notin @('password') }

    if (-not $strong) {
        Write-Finding -Level 'fail' -Text 'Password only, no second factor registered. Any policy requiring MFA will block this user until they register.'
    }
    else {
        Write-Finding -Level 'ok' -Text "Registered: $($names -join ', ')."
        if ($strong.Count -eq 1) {
            Write-Finding -Level 'warn' -Text "Only one second factor ($($strong -join ', ')). Lose the phone and the user is locked out with no self-service route."
        }
    }
}

# ---------------------------------------------------------------------------
# 3. Licences
# ---------------------------------------------------------------------------
Write-Section 'Licences'

$licences = Invoke-Safely -Label 'Licence detail' -Script {
    Get-MgUserLicenseDetail -UserId $user.Id -ErrorAction Stop
}

if ($null -ne $licences) {
    $skus = @($licences.SkuPartNumber | Sort-Object)
    $report['licences'] = $skus
    if (-not $skus) {
        Write-Finding -Level 'warn' -Text 'No licences assigned. Unlicensed users can authenticate but will be refused by most services.'
    }
    else {
        Write-Finding -Level 'ok' -Text ($skus -join ', ')
    }
}

# ---------------------------------------------------------------------------
# 4. Sign-in logs
# ---------------------------------------------------------------------------
if (-not $SkipSignInLogs) {
    Write-Section "Sign-ins, last $LookbackHours hours"

    $since  = (Get-Date).ToUniversalTime().AddHours(-$LookbackHours).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $filter = "userPrincipalName eq '$UserPrincipalName' and createdDateTime ge $since"

    $signIns = Invoke-Safely -Label 'Sign-in logs' -Script {
        Get-MgAuditLogSignIn -Filter $filter -Top $MaxSignIns -ErrorAction Stop |
            Sort-Object CreatedDateTime -Descending
    }

    if ($null -ne $signIns) {
        $failures = @($signIns | Where-Object { $_.Status.ErrorCode -ne 0 })
        $report['signInsExamined'] = @($signIns).Count
        $report['signInFailures']  = $failures.Count

        if (-not @($signIns).Count) {
            Write-Finding -Level 'info' -Text 'No sign-in records in this window. Either the user has not tried, or the client is failing before it reaches Entra ID.'
        }
        elseif (-not $failures.Count) {
            Write-Finding -Level 'ok' -Text "$(@($signIns).Count) sign-ins, none failed. Whatever the user is hitting is downstream of authentication."
        }
        else {
            Write-Finding -Level 'fail' -Text "$($failures.Count) of $(@($signIns).Count) sign-ins failed."

            $grouped = $failures | Group-Object { $_.Status.ErrorCode } | Sort-Object Count -Descending
            $detail  = @()

            foreach ($g in $grouped) {
                $code  = [int]$g.Name
                $known = $script:ErrorCodes[$code]
                $apps  = ($g.Group.AppDisplayName | Sort-Object -Unique) -join ', '

                $meaning = if ($known) { $known.Meaning } else { $g.Group[0].Status.FailureReason }
                $action  = if ($known) { $known.Action }  else { 'Look this code up in the Microsoft error reference.' }

                Write-Finding -Level 'fail' -Text "AADSTS$code x$($g.Count): $meaning"
                Write-Finding -Level 'info' -Text "   apps: $apps"
                Write-Finding -Level 'info' -Text "   next: $action"

                $detail += [pscustomobject]@{
                    errorCode = $code
                    count     = $g.Count
                    meaning   = $meaning
                    action    = $action
                    apps      = $apps
                }
            }
            $report['failureBreakdown'] = $detail
        }
    }
}

# ---------------------------------------------------------------------------
# 5. Conditional access
# ---------------------------------------------------------------------------
Write-Section 'Conditional access'

$policies = Invoke-Safely -Label 'Conditional access policies' -Script {
    Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop |
        Where-Object { $_.State -eq 'enabled' }
}

if ($null -ne $policies) {
    $groupIds = @()
    $memberOf = Invoke-Safely -Label 'Group membership' -Script {
        Get-MgUserMemberOf -UserId $user.Id -All -ErrorAction Stop
    }
    if ($memberOf) { $groupIds = @($memberOf.Id) }

    $relevant = foreach ($p in $policies) {
        $inc = $p.Conditions.Users
        $hits = $false
        if ($inc.IncludeUsers -contains 'All')      { $hits = $true }
        if ($inc.IncludeUsers -contains $user.Id)   { $hits = $true }
        if ($inc.IncludeGroups | Where-Object { $_ -in $groupIds }) { $hits = $true }

        # Exclusions win.
        if ($inc.ExcludeUsers -contains $user.Id)   { $hits = $false }
        if ($inc.ExcludeGroups | Where-Object { $_ -in $groupIds }) { $hits = $false }

        if ($hits) {
            [pscustomobject]@{
                name     = $p.DisplayName
                controls = (@($p.GrantControls.BuiltInControls) -join ', ')
            }
        }
    }

    $relevant = @($relevant)
    $report['conditionalAccess'] = $relevant

    if (-not $relevant.Count) {
        Write-Finding -Level 'info' -Text "$(@($policies).Count) enabled policies, none appear to target this user. Scoping here is an approximation, so confirm in the portal before ruling CA out."
    }
    else {
        Write-Finding -Level 'info' -Text "$($relevant.Count) enabled policies appear to target this user:"
        foreach ($r in $relevant) {
            Write-Finding -Level 'info' -Text "   $($r.name) -> $($r.controls)"
        }
        Write-Finding -Level 'warn' -Text 'Scoping above ignores app, platform, location and risk conditions. Use the portal What If tool to confirm.'
    }
}

# ---------------------------------------------------------------------------
# 6. Devices
# ---------------------------------------------------------------------------
Write-Section 'Intune devices'

$devices = Invoke-Safely -Label 'Managed devices' -Script {
    Get-MgDeviceManagementManagedDevice -Filter "userPrincipalName eq '$UserPrincipalName'" -ErrorAction Stop
}

if ($null -ne $devices) {
    $devices = @($devices)
    $report['devices'] = $devices | ForEach-Object {
        [pscustomobject]@{
            name       = $_.DeviceName
            os         = "$($_.OperatingSystem) $($_.OsVersion)"
            compliance = $_.ComplianceState
            lastSync   = $_.LastSyncDateTime
        }
    }

    if (-not $devices.Count) {
        Write-Finding -Level 'info' -Text 'No Intune devices for this user. Any policy requiring a compliant device will block them.'
    }
    foreach ($d in $devices) {
        $lvl = if ($d.ComplianceState -eq 'compliant') { 'ok' } else { 'fail' }
        $stale = if ($d.LastSyncDateTime -and ((Get-Date) - $d.LastSyncDateTime).TotalDays -gt 7) { ' (last sync over a week ago, state may be out of date)' } else { '' }
        Write-Finding -Level $lvl -Text "$($d.DeviceName), $($d.OperatingSystem) $($d.OsVersion), $($d.ComplianceState)$stale"
    }
}

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------
$fails = @($script:Findings | Where-Object Level -eq 'fail')
$warns = @($script:Findings | Where-Object Level -eq 'warn')

Write-Section 'Summary'
if ($fails.Count) {
    Write-Finding -Level 'fail' -Text "$($fails.Count) blocking issue(s). Start at the top of this list."
}
elseif ($warns.Count) {
    Write-Finding -Level 'warn' -Text "Nothing clearly blocking, $($warns.Count) thing(s) worth a look. The problem may be the client or the application rather than identity."
}
else {
    Write-Finding -Level 'ok' -Text 'Identity side looks healthy. Look at the application, the client or the network.'
}

$report['findings'] = $script:Findings
$report['durationMs'] = [int]((Get-Date) - $script:StartedAt).TotalMilliseconds

# ---------------------------------------------------------------------------
# Run metrics. No user data: counts and timings only, so this is safe to keep
# and safe to share. Needed if you ever want to say what the tool saved you.
# ---------------------------------------------------------------------------
try {
    $logDir = Join-Path $PSScriptRoot 'logs'
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    [pscustomobject]@{
        timestamp  = (Get-Date).ToString('o')
        durationMs = $report['durationMs']
        graphCalls = $script:GraphCalls
        failCount  = $fails.Count
        warnCount  = $warns.Count
    } | Export-Csv -Path (Join-Path $logDir 'triage-runs.csv') -Append -NoTypeInformation
}
catch {
    Write-Verbose "Could not write run metrics: $($_.Exception.Message)"
}

if ($OutputPath) {
    $report | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding UTF8
    if (-not $AsJson) { Write-Host "`nWritten to $OutputPath" -ForegroundColor DarkGray }
}

if ($AsJson) { $report | ConvertTo-Json -Depth 6 }

<#
  ADPOC-Script-ADResponse  (RemoteOps action script, Windows, run on the domain controller)

  Purpose : Contain an unauthorized AD user account after a detection.
  Actions : Disable      - disable the account (reversible)
            Quarantine   - disable the account and move it to the quarantine OU
  Never   : deletes accounts, removes group members, resets passwords.

  Usage (RemoteOps input string):
    -Account newuser -Action Disable
    -Account newuser -Action Quarantine -DryRun

  Safety gates (script refuses, exit code in parentheses):
    - Account name must match ^[A-Za-z0-9._-]{1,20}$      (2)  the name comes from event data
    - Account is not on the protected list                (3)
    - Account exists                                      (4)
    - Account lives under -AllowedOU                      (5)
    - Account is not a member of a privileged group       (6)
  Output  : one JSON line on stdout and in C:\ProgramData\ADPOC\response.log
  Exit    : 0 success / noop / dry run, 1 error, 2-6 refused (see above)
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Account,
  [ValidateSet('Disable', 'Quarantine')][string]$Action = 'Disable',
  [string]$AllowedOU    = 'OU=PoC-Users,DC=poc,DC=local',
  [string]$QuarantineOU = 'OU=PoC-Quarantine,DC=poc,DC=local',
  [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$logFile = 'C:\ProgramData\ADPOC\response.log'

function Write-Result {
  param([string]$Status, [string]$Detail)
  $o = [ordered]@{
    time    = (Get-Date).ToUniversalTime().ToString('o')
    host    = $env:COMPUTERNAME
    account = $Account
    action  = $Action
    dryRun  = [bool]$DryRun
    status  = $Status
    detail  = $Detail
  }
  $json = $o | ConvertTo-Json -Compress
  New-Item -ItemType Directory -Force -Path (Split-Path $logFile) | Out-Null
  Add-Content -Path $logFile -Value $json
  Write-Output $json
}

try {
  Import-Module ActiveDirectory

  if ($Account -notmatch '^[A-Za-z0-9._-]{1,20}$') {
    Write-Result 'refused' 'invalid account name'; exit 2
  }

  $protected = @('administrator', 'krbtgt', 'guest', 'bg-admin', 'svc-provision')
  if ($protected -contains $Account.ToLower()) {
    Write-Result 'refused' 'protected account'; exit 3
  }

  $u = Get-ADUser -Filter "SamAccountName -eq '$Account'" -Properties Enabled
  if (-not $u) {
    Write-Result 'refused' 'account not found'; exit 4
  }

  if ($u.DistinguishedName -notlike "*,$AllowedOU") {
    Write-Result 'refused' "account is outside $AllowedOU"; exit 5
  }

  $privileged = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
                  'Account Operators', 'Backup Operators', 'Server Operators')
  $memberOf = Get-ADPrincipalGroupMembership -Identity $u | Select-Object -ExpandProperty Name
  if ($memberOf | Where-Object { $privileged -contains $_ }) {
    Write-Result 'refused' 'account is a member of a privileged group'; exit 6
  }

  if ($DryRun) {
    Write-Result 'dryrun' "would run $Action on $($u.DistinguishedName)"; exit 0
  }

  if (-not $u.Enabled -and $Action -eq 'Disable') {
    Write-Result 'noop' 'account already disabled'; exit 0
  }

  Disable-ADAccount -Identity $u
  if ($Action -eq 'Quarantine') {
    Move-ADObject -Identity $u.DistinguishedName -TargetPath $QuarantineOU
  }

  $check = Get-ADUser -Filter "SamAccountName -eq '$Account'" -Properties Enabled
  if ($check.Enabled) { throw 'account is still enabled after Disable-ADAccount' }

  Write-Result 'success' "$Action completed"; exit 0
}
catch {
  Write-Result 'error' $_.Exception.Message; exit 1
}

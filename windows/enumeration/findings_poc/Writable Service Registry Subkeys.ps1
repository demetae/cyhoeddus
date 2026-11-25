$Root = 'HKLM:\SYSTEM\CurrentControlSet\Services'

# Write-class rights to flag.
$Rights = [ordered]@{
'SetValue' = 0x00000002
'CreateSubKey' = 0x00000004
'Delete' = 0x00010000
'WriteDACL' = 0x00040000
'WriteOwner' = 0x00080000
'GenericAll' = 0x10000000
'GenericWrite' = 0x40000000
}

# Rights that change existing state (vs. only adding subkeys).
$ModifyMask = 0x00000002 -bor 0x00010000 -bor 0x00040000 -bor 0x00080000 -bor 0x10000000 -bor 0x40000000

# SIDs the current user holds (own SID plus group memberships).
$Me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$MySids = New-Object 'System.Collections.Generic.HashSet[string]'
[void] $MySids.Add($Me.User.Value)
foreach ($g in $Me.Groups) { [void] $MySids.Add($g.Value) }

# Inspect one key's ACL and emit any matching, user-held permissions.
function Test-Key {
param($KeyPath, $ServiceName, $RunAs, $Scope)
$Acl = Get-Acl -Path $KeyPath -ErrorAction SilentlyContinue
if (-not $Acl) { return }
foreach ($Ace in $Acl.Access) {
if ($Ace.AccessControlType -ne 'Allow') { continue }
try { $Sid = $Ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
catch { $Sid = $Ace.IdentityReference.Value }
if (-not $MySids.Contains($Sid)) { continue }
$Mask = [int] $Ace.RegistryRights
$Matched = @($Rights.Keys | Where-Object { $Mask -band $Rights[$_] })
if ($Matched.Count -eq 0) { continue }
New-Object PSObject -Property @{
Service = $ServiceName
Scope = $Scope
Key = $KeyPath -replace '.*::', ''
Identity = $Ace.IdentityReference.Value
Rights = $Matched -join ', '
Signal = if ($Mask -band $ModifyMask) { 'Modify' } else { 'Subkey-only' }
Inherited = $Ace.IsInherited
RunAs = $RunAs
}
}
}

# Walk each service: check its key, then its immediate subkeys. Skip drivers and keys with no image path.
$Results = foreach ($Svc in Get-ChildItem -Path $Root -ErrorAction SilentlyContinue) {
$Props = Get-ItemProperty -Path $Svc.PSPath -ErrorAction SilentlyContinue
if (-not $Props.ImagePath) { continue }
if ($Props.Type -eq 1 -or $Props.Type -eq 2) { continue }
$RunAs = $Props.ObjectName

Test-Key -KeyPath $Svc.PSPath -ServiceName $Svc.PSChildName -RunAs $RunAs -Scope 'Root'

foreach ($Sub in Get-ChildItem -Path $Svc.PSPath -ErrorAction SilentlyContinue) {
Test-Key -KeyPath $Sub.PSPath -ServiceName $Svc.PSChildName -RunAs $RunAs -Scope 'Subkey'
}
}

# Output.
$CsvPath = Join-Path $PWD "$($env:COMPUTERNAME)_ServiceRegistryPermissions.csv"

"Host: $env:COMPUTERNAME | User: $env:USERNAME | Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
''

if (-not $Results) {
    'RESULT: No matching writable service registry ACL entries found.'
}
else {
    $Results |
        Sort-Object Signal, Scope, Service |
        Select-Object `
            @{Name='Host';Expression={$env:COMPUTERNAME}},
            @{Name='User';Expression={$env:USERNAME}},
            @{Name='Date';Expression={Get-Date -Format 'yyyy-MM-dd HH:mm'}},
            Service, Scope, Key, Identity, Rights, Signal, Inherited, RunAs |
        Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

    $Modify = @($Results | Where-Object { $_.Signal -eq 'Modify' })

    "RESULT: $(@($Results).Count) entries; $($Modify.Count) of 'Modify' class."

    if ($Modify.Count -gt 0) {
        'Modify-class entries allow existing values/permissions to be changed - investigate these first.'
    }

    "CSV saved to: $CsvPath"
}
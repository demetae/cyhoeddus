$Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
$Settings = 'DenyDeviceClasses', 'DenyDeviceIDs', 'DenyInstanceIDs', 'DenyRemovableDevices', 'DenyUnspecified',
'AllowDenyLayered', 'AllowDeviceClasses', 'AllowDeviceIDs', 'AllowInstanceIDs'

$Policy = Get-ItemProperty -Path $Key -ErrorAction SilentlyContinue
$Results = foreach ($Name in $Settings) {
$Value = if ($Policy) { $Policy.$Name }
$State = if ($null -eq $Value) { 'Not Configured' } elseif ($Value -eq 0) { 'Disabled' } else { 'Enabled' }
$List = Get-ItemProperty -Path "$Key\$Name" -ErrorAction SilentlyContinue
$Entries = if ($List) { ($List.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $_.Value }) -join '; ' }
New-Object PSObject -Property @{ Setting = $Name; State = $State; Entries = $Entries }
}

"Host: $env:COMPUTERNAME | User: $env:USERNAME | Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
"Policy key present: $(Test-Path $Key)"
($Results | Format-Table Setting, State, Entries -AutoSize | Out-String -Width 200).TrimEnd()
''

$NotSet = @($Results | Where-Object { $_.State -eq 'Not Configured' }).Count
$Deny = @($Results | Where-Object { $_.Setting -like 'Deny*' -and $_.State -eq 'Enabled' })
"Not Configured: $NotSet of $($Settings.Count) settings"
if ($Deny.Count -eq 0) { 'RESULT: No Deny policy is defined. USB device installation is not restricted.' }
else { 'RESULT: Deny policy defined (' + (($Deny | ForEach-Object { $_.Setting }) -join ', ') + '). Review the entries above.' }
$keys = @(
'HKLM:\Software\Microsoft\Policies\LAPS',
'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS',
'HKLM:\Software\Microsoft\Windows\CurrentVersion\LAPS\Config',
'HKLM:\Software\Policies\Microsoft Services\AdmPwd'
)
foreach ($k in $keys) {
if (Test-Path $k) { "[$k]"; Get-ItemProperty $k | Select-Object * -ExcludeProperty PS* | Format-List }
else { "[$k] not present" }
}
function Get-PSFeature {
param($RelPath, $Name)
$u = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\PowerShell$RelPath" -Name $Name -ErrorAction SilentlyContinue).$Name
if ($null -ne $u) { return $u }
(Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell$RelPath" -Name $Name -ErrorAction SilentlyContinue).$Name
}
function Get-PSModuleList {
foreach ($hive in 'HKCU','HKLM') {
$p = Get-ItemProperty "$hive`:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -ErrorAction SilentlyContinue
if ($p) { return (($p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $_.Name }) -join ', ') }
}
}

$enableScripts = Get-PSFeature '' 'EnableScripts'
$execPolicy = Get-PSFeature '' 'ExecutionPolicy'
$sbl = Get-PSFeature '\ScriptBlockLogging' 'EnableScriptBlockLogging'
$ml = Get-PSFeature '\ModuleLogging' 'EnableModuleLogging'
$mlList = Get-PSModuleList
$ts = Get-PSFeature '\Transcription' 'EnableTranscripting'
$tsDir = Get-PSFeature '\Transcription' 'OutputDirectory'

$desc = ""
if ([string]::IsNullOrEmpty($execPolicy)) { $desc += "No execution policy is enforced. " }
if ($execPolicy -eq "Unrestricted") { $desc += "All scripts are allowed to run. " }
if (-not $sbl) { $desc += "Script block logging is not enabled. " }
if (-not $ml) { $desc += "Module logging is not enabled. " }
if ([string]::IsNullOrEmpty($desc)) { $desc = "No particular issue was observed." }

[PSCustomObject]@{
EnableScripts = if ($null -ne $enableScripts) { [bool]$enableScripts } else { $null }
ExecutionPolicy = $execPolicy
ScriptBlockLoggingEnabled = if ($null -ne $sbl) { [bool]$sbl } else { $null }
ModuleLoggingEnabled = if ($null -ne $ml) { [bool]$ml } else { $null }
ModuleLoggingModuleList = $mlList
TranscriptionEnabled = if ($null -ne $ts) { [bool]$ts } else { $null }
TranscriptionDirectory = $tsDir
Description = $desc
} | Format-List
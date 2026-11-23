$key = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
$runAsPPL = (Get-ItemProperty -Path "Registry::$key" -Name 'RunAsPPL' -ErrorAction SilentlyContinue).RunAsPPL
$runAsPPLBoot = (Get-ItemProperty -Path "Registry::$key" -Name 'RunAsPPLBoot' -ErrorAction SilentlyContinue).RunAsPPLBoot
if ($null -eq $runAsPPL) { $runAsPPL = 0 }
if ($null -eq $runAsPPLBoot) { $runAsPPLBoot = 0 }

[PSCustomObject]@{
Key = $key
RunAsPPL = $runAsPPL
RunAsPPLBoot = $runAsPPLBoot
Description = if ($runAsPPL -ge 1) { 'LSA Protection is enabled.' } else { 'LSA Protection is not enabled.' }
} | Format-List
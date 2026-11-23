# Credential Guard configuration (read-only)
$policyKey = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
$lsaKey = 'HKLM\SYSTEM\CurrentControlSet\Control\LSA'
$valueName = 'LsaCfgFlags' # 0=disabled, 1=enabled w/ UEFI lock, 2=enabled w/o lock

$policyData = (Get-ItemProperty -Path "Registry::$policyKey" -Name $valueName -ErrorAction SilentlyContinue).$valueName
$lsaData = (Get-ItemProperty -Path "Registry::$lsaKey" -Name $valueName -ErrorAction SilentlyContinue).$valueName

# Policy value takes precedence over the LSA key
$effective = if ($null -ne $policyData) { $policyData } elseif ($null -ne $lsaData) { $lsaData } else { $null }
$lsaDesc = switch ($effective) {
0 { 'Credential Guard is explicitly disabled.' }
1 { 'Credential Guard is enabled with UEFI lock.' }
2 { 'Credential Guard is enabled without UEFI lock.' }
default { 'Credential Guard is not configured.' }
}

# Actual runtime state (service id 1 = Credential Guard)
$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction SilentlyContinue
$configured = [bool]($dg.SecurityServicesConfigured -contains 1)
$running = [bool]($dg.SecurityServicesRunning -contains 1)
$cgDesc = "$(if ($configured) {'Credential Guard is configured.'} else {'Credential Guard is not configured.'}) " +
"$(if ($running) {'Credential Guard is running.'} else {'Credential Guard is not running.'})"

[PSCustomObject]@{
LsaCfgFlagsPolicyKey = $policyKey
LsaCfgFlagsPolicyValue = $valueName
LsaCfgFlagsPolicyData = if ($null -ne $policyData) { $policyData } else { '(null)' }
LsaCfgFlagsKey = $lsaKey
LsaCfgFlagsValue = $valueName
LsaCfgFlagsData = if ($null -ne $lsaData) { $lsaData } else { '(null)' }
LsaCfgFlagsDescription = $lsaDesc
CredentialGuardConfigured = $configured
CredentialGuardRunning = $running
CredentialGuardDescription = $cgDesc
} | Format-List
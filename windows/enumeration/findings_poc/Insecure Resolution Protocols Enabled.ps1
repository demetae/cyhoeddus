function Get-RegData { param($Path,$Name) (Get-ItemProperty -Path "Registry::$Path" -Name $Name -ErrorAction SilentlyContinue).$Name }

$llmnr = Get-RegData 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
$nbt = Get-RegData 'HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' 'NodeType'
$mdns = Get-RegData 'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' 'EnableMDNS'

@(
[PSCustomObject]@{
Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Value='EnableMulticast'
Data= if ($null -ne $llmnr) { $llmnr } else { '(null)' }
Description= switch ($llmnr) {
0 {'Multicast name resolution (LLMNR) is disabled.'}
1 {'Multicast name resolution (LLMNR) is enabled.'}
default {'Multicast name resolution (LLMNR) is enabled (default).'} }
}
[PSCustomObject]@{
Key='HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'; Value='NodeType'
Data= if ($null -ne $nbt) { $nbt } else { '(null)' }
Description= switch ($nbt) {
1 {'The NetBIOS node type is B-node - Broadcast.'}
2 {'The NetBIOS node type is P-node - Point-to-point.'}
4 {'The NetBIOS node type is M-node - Mixed.'}
8 {'The NetBIOS node type is H-node - Hybrid.'}
default {'The NetBIOS node type is B-node (default) - Broadcast.'} }
}
[PSCustomObject]@{
Key='HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'; Value='EnableMDNS'
Data= if ($null -ne $mdns) { $mdns } else { '(null)' }
Description= switch ($mdns) {
0 {'Multicast DNS (mDNS) is disabled.'}
1 {'Multicast DNS (mDNS) is enabled.'}
default {'Multicast DNS (mDNS) is enabled (default).'} }
}
) | Format-List Key, Value, Data, Description
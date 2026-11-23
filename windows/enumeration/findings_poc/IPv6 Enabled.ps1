$key = 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
$data = (Get-ItemProperty -Path "Registry::$key" -Name 'DisabledComponents' -ErrorAction SilentlyContinue).DisabledComponents
$isDefault = ($null -eq $data)
$dc = if ($isDefault) { 0 } else { [int64]$data }
$tag = if ($isDefault) { ' (default)' } else { '' }
$preferIPv4 = [bool]($dc -band 0x20) # bit 5
$disTunnel = [bool]($dc -band 0x01) # bit 0
$disNonTunnel = [bool]($dc -band 0x10) # bit 4
$desc = @(
if ($preferIPv4) { "IPv4 is preferred over IPv6$tag." } else { "IPv6 is preferred over IPv4$tag." }
if ($disTunnel) { "IPv6 is disabled on all tunnel interfaces$tag." } else { "IPv6 is enabled on all tunnel interfaces$tag." }
if ($disNonTunnel) { "IPv6 is disabled on all non-tunnel interfaces$tag." } else { "IPv6 is enabled on all non-tunnel interfaces$tag." }
) -join ' '
[PSCustomObject]@{
Key = $key
Value = 'DisabledComponents'
Data = if ($isDefault) { '(null)' } else { $data }
Default = 0
PreferIPv4OverIPv6 = $preferIPv4
DisableIPv6OnAllTunnelInterfaces = $disTunnel
DisableIPv6OnAllNonTunnelInterfaces = $disNonTunnel
Description = $desc
} | Format-List
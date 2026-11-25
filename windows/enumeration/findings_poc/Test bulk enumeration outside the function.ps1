$Root = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
    'SYSTEM\CurrentControlSet\Services'
)

$Root.GetSubKeyNames() | Select-Object -First 10
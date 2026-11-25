$Root = 'HKLM:\SYSTEM\CurrentControlSet\Services'

foreach ($Svc in Get-ChildItem -LiteralPath $Root) {

    $Path = "Registry::$($Svc.Name)"

    try {
        $Acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        Write-Host "OK: $Path" -ForegroundColor Green
    }
    catch {
        Write-Host "FAILED: $Path" -ForegroundColor Red
        Write-Host $_.Exception.Message
    }
}
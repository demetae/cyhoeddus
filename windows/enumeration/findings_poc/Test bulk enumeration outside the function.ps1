Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
ForEach-Object {
    try {
        $Acl = Get-Acl -LiteralPath $_.PSPath -ErrorAction Stop
        Write-Host "OK: $($_.PSChildName)" -ForegroundColor Green
    }
    catch {
        Write-Host "FAILED: $($_.PSPath)" -ForegroundColor Red
        Write-Host $_.Exception.Message
    }
}
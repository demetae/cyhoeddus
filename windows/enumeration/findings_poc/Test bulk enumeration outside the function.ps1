foreach ($Name in $Root.GetSubKeyNames()) {

    $Key = $null

    try {
        $Key = $Root.OpenSubKey($Name)

        if ($null -eq $Key) {
            Write-Warning "Unable to open: $Name"
            continue
        }

        $Acl = $Key.GetAccessControl()

        Write-Host "OK: $Name" -ForegroundColor Green
    }
    catch {
        Write-Host "FAILED: $Name" -ForegroundColor Red
        Write-Host $_.Exception.Message
    }
    finally {
        if ($null -ne $Key) {
            $Key.Close()
        }
    }
}

$Root.Close()
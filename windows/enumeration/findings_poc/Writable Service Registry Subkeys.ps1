$Root = 'HKLM:\SYSTEM\CurrentControlSet\Services'

$CsvPath = Join-Path $PWD "$($env:COMPUTERNAME)_ServiceRegistryPermissions.csv"
$ScanDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

# Write-class rights to flag.
$Rights = [ordered]@{
    'SetValue'     = 0x00000002
    'CreateSubKey' = 0x00000004
    'Delete'       = 0x00010000
    'WriteDACL'    = 0x00040000
    'WriteOwner'   = 0x00080000
    'GenericAll'   = 0x10000000
    'GenericWrite' = 0x40000000
}

# Rights that change existing state.
$ModifyMask = 0x00000002 -bor
              0x00010000 -bor
              0x00040000 -bor
              0x00080000 -bor
              0x10000000 -bor
              0x40000000

# Obtain current user SID and group memberships.
$Me = [System.Security.Principal.WindowsIdentity]::GetCurrent()

$MySids = New-Object 'System.Collections.Generic.HashSet[string]'

[void] $MySids.Add($Me.User.Value)

foreach ($g in $Me.Groups) {
    [void] $MySids.Add($g.Value)
}

# Check whether the current session is elevated.
$Principal = New-Object System.Security.Principal.WindowsPrincipal($Me)

if ($Principal.IsInRole(
    [System.Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    Write-Warning 'Running as administrator. Results may be misleading.'
}

# Track registry keys whose ACLs could not be read.
$script:UnreadableKeys = 0

# Safely retrieve optional registry properties.
function Get-OptionalProperty {
    param(
        $Object,
        [string] $Name
    )

    if ($null -ne $Object) {
        $Property = $Object.PSObject.Properties[$Name]

        if ($null -ne $Property) {
            return $Property.Value
        }
    }

    return $null
}

# Inspect registry key ACLs.
function Test-Key {
    param(
        $KeyPath,
        $ServiceName,
        $RunAs,
        $Scope,
        $ImagePath,
        $ServiceType
    )

    try {
        $Acl = Get-Acl -LiteralPath $KeyPath -ErrorAction Stop
    }
    catch {
        $script:UnreadableKeys++
        return
    }

    foreach ($Ace in $Acl.Access) {

        if ($Ace.AccessControlType -ne 'Allow') {
            continue
        }

        # Skip ACEs that apply only to child objects.
        if ($Ace.PropagationFlags -band
            [System.Security.AccessControl.PropagationFlags]::InheritOnly) {
            continue
        }

        try {
            $Sid = $Ace.IdentityReference.Translate(
                [System.Security.Principal.SecurityIdentifier]
            ).Value
        }
        catch {
            $Sid = $Ace.IdentityReference.Value
        }

        if (-not $MySids.Contains($Sid)) {
            continue
        }

        $Mask = [int] $Ace.RegistryRights

        $Matched = @(
            $Rights.Keys | Where-Object {
                $Mask -band $Rights[$_]
            }
        )

        if ($Matched.Count -eq 0) {
            continue
        }

        [PSCustomObject][ordered]@{
            Host        = $env:COMPUTERNAME
            User        = $Me.Name
            Date        = $ScanDate
            Service     = $ServiceName
            Scope       = $Scope
            Key         = $KeyPath -replace '.*::', ''
            Identity    = $Ace.IdentityReference.Value
            Rights      = $Matched -join ', '
            Signal      = if ($Mask -band $ModifyMask) {
                'Modify'
            }
            else {
                'Subkey-only'
            }
            Inherited   = $Ace.IsInherited
            RunAs       = $RunAs
            ImagePath   = $ImagePath
            ServiceType = $ServiceType
        }
    }
}

# Enumerate service registry keys.
$Results = @(
    foreach ($Svc in Get-ChildItem -LiteralPath $Root `
        -ErrorAction SilentlyContinue) {

        $Props = Get-ItemProperty -LiteralPath $Svc.PSPath `
            -ErrorAction SilentlyContinue

        # Retrieve optional properties safely.
        $ImagePath = Get-OptionalProperty $Props 'ImagePath'
        $ServiceType = Get-OptionalProperty $Props 'Type'
        $RunAs = Get-OptionalProperty $Props 'ObjectName'

        # Skip known driver types.
        if ($null -ne $ServiceType) {
            if ([int]$ServiceType -band 0x0F) {
                continue
            }
        }

        # Missing properties do not prevent ACL inspection.
        if (-not $ImagePath) {
            $ImagePath = 'Not configured or unreadable'
        }

        if (-not $RunAs) {
            $RunAs = 'Unknown'
        }

        if ($null -eq $ServiceType) {
            $ServiceType = 'Unknown'
        }

        # Inspect service root key.
        Test-Key `
            -KeyPath $Svc.PSPath `
            -ServiceName $Svc.PSChildName `
            -RunAs $RunAs `
            -Scope 'Root' `
            -ImagePath $ImagePath `
            -ServiceType $ServiceType

        # Inspect immediate service subkeys.
        foreach ($Sub in Get-ChildItem -LiteralPath $Svc.PSPath `
            -ErrorAction SilentlyContinue) {

            Test-Key `
                -KeyPath $Sub.PSPath `
                -ServiceName $Svc.PSChildName `
                -RunAs $RunAs `
                -Scope 'Subkey' `
                -ImagePath $ImagePath `
                -ServiceType $ServiceType
        }
    }
)

# Sort findings.
$Results = @(
    $Results | Sort-Object Signal, Scope, Service
)

# Export findings to CSV.
if ($Results.Count -gt 0) {
    $Results | Export-Csv `
        -LiteralPath $CsvPath `
        -NoTypeInformation `
        -Encoding UTF8
}
else {
    # Create a header-only CSV when no findings exist.
    '"Host","User","Date","Service","Scope","Key","Identity","Rights","Signal","Inherited","RunAs","ImagePath","ServiceType"' |
        Set-Content -LiteralPath $CsvPath -Encoding UTF8
}

# Console summary.
$Modify = @(
    $Results | Where-Object { $_.Signal -eq 'Modify' }
)

$SubkeyOnly = @(
    $Results | Where-Object { $_.Signal -eq 'Subkey-only' }
)

Write-Host ''
Write-Host "Host:          $env:COMPUTERNAME"
Write-Host "User:          $($Me.Name)"
Write-Host "Date:          $ScanDate"
Write-Host ''
Write-Host "Total entries: $($Results.Count)"
Write-Host "Modify:        $($Modify.Count)"
Write-Host "Subkey-only:   $($SubkeyOnly.Count)"
Write-Host "Unreadable:    $script:UnreadableKeys"
Write-Host ''

if ($Results.Count -eq 0) {
    Write-Host 'RESULT: No matching writable service registry ACL entries found.' `
        -ForegroundColor Green
}
else {
    Write-Host 'RESULT: Potentially writable service registry keys identified.' `
        -ForegroundColor Yellow
}

if ($Modify.Count -gt 0) {
    Write-Host 'Prioritise investigation of Modify-class entries.' `
        -ForegroundColor Yellow
}

Write-Host ''
Write-Host "CSV saved to: $CsvPath" -ForegroundColor Cyan
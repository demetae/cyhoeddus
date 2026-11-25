$Root = 'HKLM:\SYSTEM\CurrentControlSet\Services'

$CsvPath = Join-Path $PWD "$($env:COMPUTERNAME)_ServiceRegistryPermissions.csv"
$ErrorCsvPath = Join-Path $PWD "$($env:COMPUTERNAME)_ServiceRegistryErrors.csv"
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

# Initialise counters and error collection.
$script:UnreadableKeys = 0
$script:ReadableKeys = 0
$script:TotalKeys = 0
$script:SkippedDrivers = 0
$script:ScanErrors = New-Object 'System.Collections.Generic.List[object]'

# Record enumeration errors.
function Add-ScanError {
    param(
        $KeyPath,
        $ServiceName,
        $Operation,
        $ErrorRecord
    )

    $script:ScanErrors.Add(
        [PSCustomObject][ordered]@{
            Host          = $env:COMPUTERNAME
            User          = $Me.Name
            Date          = $ScanDate
            Service       = $ServiceName
            Key           = $KeyPath -replace '.*::', ''
            Operation     = $Operation
            Error         = $ErrorRecord.Exception.Message
            ExceptionType = $ErrorRecord.Exception.GetType().FullName
            ErrorId       = $ErrorRecord.FullyQualifiedErrorId
        }
    )

    Write-Warning "$Operation failed: $KeyPath"
    Write-Warning $ErrorRecord.Exception.Message
}

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

    $script:TotalKeys++

    try {
        $Acl = Get-Acl -LiteralPath $KeyPath -ErrorAction Stop
        $script:ReadableKeys++
    }
    catch {
        $script:UnreadableKeys++

        Add-ScanError `
            -KeyPath $KeyPath `
            -ServiceName $ServiceName `
            -Operation 'Get-Acl' `
            -ErrorRecord $_

        return
    }

    foreach ($Ace in $Acl.Access) {

        if ($Ace.AccessControlType -ne 'Allow') {
            continue
        }

        # Skip ACEs that only apply to child objects.
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
try {
    $Services = @(
        Get-ChildItem -LiteralPath $Root -ErrorAction Stop
    )
}
catch {
    Add-ScanError `
        -KeyPath $Root `
        -ServiceName 'N/A' `
        -Operation 'Enumerate services' `
        -ErrorRecord $_

    $Services = @()
}

$Results = @(
    foreach ($Svc in $Services) {

        $Props = $null

        try {
            $Props = Get-ItemProperty `
                -LiteralPath $Svc.PSPath `
                -ErrorAction Stop
        }
        catch {
            Add-ScanError `
                -KeyPath $Svc.PSPath `
                -ServiceName $Svc.PSChildName `
                -Operation 'Get-ItemProperty' `
                -ErrorRecord $_
        }

        # Safely retrieve optional registry properties.
        $ImagePath = Get-OptionalProperty $Props 'ImagePath'
        $ServiceType = Get-OptionalProperty $Props 'Type'
        $RunAs = Get-OptionalProperty $Props 'ObjectName'

        # Skip known driver service types.
        if ($null -ne $ServiceType) {
            if ([int]$ServiceType -band 0x0F) {
                $script:SkippedDrivers++
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

        # Enumerate immediate service subkeys.
        $Subkeys = @()

        try {
            $Subkeys = @(
                Get-ChildItem `
                    -LiteralPath $Svc.PSPath `
                    -ErrorAction Stop
            )
        }
        catch {
            Add-ScanError `
                -KeyPath $Svc.PSPath `
                -ServiceName $Svc.PSChildName `
                -Operation 'Enumerate subkeys' `
                -ErrorRecord $_
        }

        # Inspect immediate service subkeys.
        foreach ($Sub in $Subkeys) {

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

# Export findings.
if ($Results.Count -gt 0) {
    $Results | Export-Csv `
        -LiteralPath $CsvPath `
        -NoTypeInformation `
        -Encoding UTF8
}
else {
    '"Host","User","Date","Service","Scope","Key","Identity","Rights","Signal","Inherited","RunAs","ImagePath","ServiceType"' |
        Set-Content -LiteralPath $CsvPath -Encoding UTF8
}

# Export enumeration errors.
if ($script:ScanErrors.Count -gt 0) {
    $script:ScanErrors | Export-Csv `
        -LiteralPath $ErrorCsvPath `
        -NoTypeInformation `
        -Encoding UTF8
}
else {
    '"Host","User","Date","Service","Key","Operation","Error","ExceptionType","ErrorId"' |
        Set-Content -LiteralPath $ErrorCsvPath -Encoding UTF8
}

# Calculate findings.
$Modify = @(
    $Results | Where-Object { $_.Signal -eq 'Modify' }
)

$SubkeyOnly = @(
    $Results | Where-Object { $_.Signal -eq 'Subkey-only' }
)

# Calculate ACL read success rate.
$Coverage = if ($script:TotalKeys -gt 0) {
    [math]::Round(
        ($script:ReadableKeys / $script:TotalKeys) * 100,
        2
    )
}
else {
    0
}

# Console summary.
Write-Host ''
Write-Host '========== SERVICE REGISTRY ACL AUDIT =========='
Write-Host ''
Write-Host "Host:             $env:COMPUTERNAME"
Write-Host "User:             $($Me.Name)"
Write-Host "Date:             $ScanDate"
Write-Host ''
Write-Host "Service keys:     $($Services.Count)"
Write-Host "Drivers skipped:  $script:SkippedDrivers"
Write-Host "ACLs attempted:   $script:TotalKeys"
Write-Host "ACLs readable:    $script:ReadableKeys"
Write-Host "ACLs unreadable:  $script:UnreadableKeys"
Write-Host "ACL read success: $Coverage%"
Write-Host "Total errors:     $($script:ScanErrors.Count)"
Write-Host ''
Write-Host "Total findings:   $($Results.Count)"
Write-Host "Modify:           $($Modify.Count)"
Write-Host "Subkey-only:      $($SubkeyOnly.Count)"
Write-Host ''

if ($Results.Count -gt 0) {
    Write-Host 'RESULT: Potentially writable service registry keys identified.' `
        -ForegroundColor Yellow
}
elseif ($script:ScanErrors.Count -gt 0 -or $script:TotalKeys -eq 0) {
    Write-Host 'RESULT: INCONCLUSIVE - enumeration incomplete.' `
        -ForegroundColor Yellow
}
else {
    Write-Host 'RESULT: No matching writable service registry ACL entries found.' `
        -ForegroundColor Green
}

if ($script:ScanErrors.Count -gt 0) {
    Write-Host 'WARNING: Assessment coverage is incomplete.' `
        -ForegroundColor Yellow
}

if ($Modify.Count -gt 0) {
    Write-Host 'Prioritise investigation of Modify-class entries.' `
        -ForegroundColor Yellow
}

# Summarise errors by message.
if ($script:ScanErrors.Count -gt 0) {

    Write-Host ''
    Write-Host '========== ERROR SUMMARY =========='

    $script:ScanErrors |
        Group-Object Operation, Error |
        Sort-Object Count -Descending |
        Select-Object Count, Name |
        Format-Table -AutoSize -Wrap
}

Write-Host ''
Write-Host "Findings CSV: $CsvPath" -ForegroundColor Cyan
Write-Host "Errors CSV:   $ErrorCsvPath" -ForegroundColor Cyan
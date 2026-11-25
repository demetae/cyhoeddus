$Root = 'HKLM:\SYSTEM\CurrentControlSet\Services'

# Enable detailed debugging.
$DebugMode = $true

# Output files.
$CsvPath = Join-Path $PWD "$($env:COMPUTERNAME)_ServiceRegistryPermissions.csv"
$ErrorCsvPath = Join-Path $PWD "$($env:COMPUTERNAME)_ServiceRegistryErrors.csv"
$ScanDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

# Write-class registry rights.
$Rights = [ordered]@{
    'SetValue'     = 0x00000002
    'CreateSubKey' = 0x00000004
    'Delete'       = 0x00010000
    'WriteDACL'    = 0x00040000
    'WriteOwner'   = 0x00080000
    'GenericAll'   = 0x10000000
    'GenericWrite' = 0x40000000
}

$ModifyMask = (
    0x00000002 -bor
    0x00010000 -bor
    0x00040000 -bor
    0x00080000 -bor
    0x10000000 -bor
    0x40000000
)

# Obtain current user identity.
$Me = [System.Security.Principal.WindowsIdentity]::GetCurrent()

$MySids = New-Object 'System.Collections.Generic.HashSet[string]'

[void]$MySids.Add($Me.User.Value)

foreach ($Group in $Me.Groups) {
    [void]$MySids.Add($Group.Value)
}

# Check elevation.
$Principal = New-Object System.Security.Principal.WindowsPrincipal($Me)

if ($Principal.IsInRole(
    [System.Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    Write-Warning 'Running as administrator. Results may be misleading.'
}

# Initialise collections and counters.
$script:Results = New-Object 'System.Collections.Generic.List[object]'
$script:ScanErrors = New-Object 'System.Collections.Generic.List[object]'

$script:TotalKeys = 0
$script:ReadableKeys = 0
$script:UnreadableKeys = 0
$script:SkippedDrivers = 0

# Safely retrieve optional properties.
function Get-OptionalProperty {
    param(
        $Object,
        [string]$Name
    )

    if ($null -ne $Object) {
        $Property = $Object.PSObject.Properties[$Name]

        if ($null -ne $Property) {
            return $Property.Value
        }
    }

    return $null
}

# Record errors.
function Add-ScanError {
    param(
        [string]$KeyPath,
        [string]$ServiceName,
        [string]$Operation,
        $ErrorRecord
    )

    $Entry = [PSCustomObject][ordered]@{
        Host      = $env:COMPUTERNAME
        User      = $Me.Name
        Date      = $ScanDate
        Service   = $ServiceName
        Key       = $KeyPath
        Operation = $Operation
        Error     = $ErrorRecord.Exception.Message
        ErrorId   = $ErrorRecord.FullyQualifiedErrorId
    }

    [void]$script:ScanErrors.Add($Entry)

    Write-Warning "$Operation failed: [$KeyPath]"
    Write-Warning $ErrorRecord.Exception.Message
}

# Inspect a registry key.
function Test-ServiceRegistryKey {
    param(
        [string]$KeyPath,
        [string]$ServiceName,
        [string]$RunAs,
        [string]$Scope,
        [string]$ImagePath,
        [string]$ServiceType
    )

    $script:TotalKeys++

    if ($DebugMode) {
        Write-Host "DEBUG: [$KeyPath]" -ForegroundColor Cyan
        Write-Host "Type: $($KeyPath.GetType().FullName)"
    }

    try {
        if ($DebugMode) {
            $Exists = Test-Path -LiteralPath $KeyPath
            Write-Host "Exists: $Exists"
        }

        $Acl = Get-Acl -LiteralPath $KeyPath -ErrorAction Stop

        $script:ReadableKeys++

        if ($DebugMode) {
            Write-Host 'ACL read successful.' -ForegroundColor Green
        }
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

        # Only inspect Allow ACEs.
        if ($Ace.AccessControlType -ne 'Allow') {
            continue
        }

        # Ignore ACEs that apply only to child objects.
        if ($Ace.PropagationFlags -band
            [System.Security.AccessControl.PropagationFlags]::InheritOnly) {
            continue
        }

        # Resolve identity to SID.
        try {
            $Sid = $Ace.IdentityReference.Translate(
                [System.Security.Principal.SecurityIdentifier]
            ).Value
        }
        catch {
            $Sid = $Ace.IdentityReference.Value
        }

        # Check whether the current user holds this SID.
        if (-not $MySids.Contains($Sid)) {
            continue
        }

        $Mask = [int]$Ace.RegistryRights

        $Matched = @(
            $Rights.Keys | Where-Object {
                $Mask -band $Rights[$_]
            }
        )

        if ($Matched.Count -eq 0) {
            continue
        }

        # Classify permissions.
        if ($Mask -band $ModifyMask) {
            $Signal = 'Modify'
        }
        else {
            $Signal = 'Subkey-only'
        }

        $MatchedRights = ($Matched -join ', ')
        $CleanPath = ($KeyPath -replace '.*::', '')

        $Finding = [PSCustomObject][ordered]@{
            Host        = $env:COMPUTERNAME
            User        = $Me.Name
            Date        = $ScanDate
            Service     = $ServiceName
            Scope       = $Scope
            Key         = $CleanPath
            Identity    = $Ace.IdentityReference.Value
            Rights      = $MatchedRights
            Signal      = $Signal
            Inherited   = $Ace.IsInherited
            RunAs       = $RunAs
            ImagePath   = $ImagePath
            ServiceType = $ServiceType
        }

        [void]$script:Results.Add($Finding)

        Write-Host "FINDING: $ServiceName - $MatchedRights" `
            -ForegroundColor Yellow
    }
}

# Enumerate service registry keys.
$Services = @()

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
}

Write-Host "Discovered $($Services.Count) service registry keys."

# Inspect each service.
foreach ($Svc in $Services) {

    $ServiceName = [string]$Svc.PSChildName
    $ServicePath = [string]$Svc.PSPath

    $Props = $null

    try {
        $Props = Get-ItemProperty `
            -LiteralPath $ServicePath `
            -ErrorAction Stop
    }
    catch {
        Add-ScanError `
            -KeyPath $ServicePath `
            -ServiceName $ServiceName `
            -Operation 'Get-ItemProperty' `
            -ErrorRecord $_
    }

    # Read optional service properties.
    $ImagePath = Get-OptionalProperty $Props 'ImagePath'
    $ServiceType = Get-OptionalProperty $Props 'Type'
    $RunAs = Get-OptionalProperty $Props 'ObjectName'

    # Skip known driver types.
    if ($null -ne $ServiceType) {
        if ([int]$ServiceType -band 0x0F) {
            $script:SkippedDrivers++
            continue
        }
    }

    if (-not $ImagePath) {
        $ImagePath = 'Not configured or unreadable'
    }

    if (-not $RunAs) {
        $RunAs = 'Unknown'
    }

    if ($null -eq $ServiceType) {
        $ServiceType = 'Unknown'
    }

    # Inspect the service root key.
    Test-ServiceRegistryKey `
        -KeyPath $ServicePath `
        -ServiceName $ServiceName `
        -RunAs $RunAs `
        -Scope 'Root' `
        -ImagePath $ImagePath `
        -ServiceType $ServiceType

    # Enumerate immediate subkeys.
    $Subkeys = @()

    try {
        $Subkeys = @(
            Get-ChildItem `
                -LiteralPath $ServicePath `
                -ErrorAction Stop
        )
    }
    catch {
        Add-ScanError `
            -KeyPath $ServicePath `
            -ServiceName $ServiceName `
            -Operation 'Enumerate subkeys' `
            -ErrorRecord $_
    }

    foreach ($Sub in $Subkeys) {

        $SubPath = [string]$Sub.PSPath

        Test-ServiceRegistryKey `
            -KeyPath $SubPath `
            -ServiceName $ServiceName `
            -RunAs $RunAs `
            -Scope 'Subkey' `
            -ImagePath $ImagePath `
            -ServiceType $ServiceType
    }
}

# Sort findings.
$SortedResults = @(
    $script:Results |
        Sort-Object Signal, Scope, Service
)

# Export findings CSV.
if ($SortedResults.Count -gt 0) {
    $SortedResults | Export-Csv `
        -LiteralPath $CsvPath `
        -NoTypeInformation `
        -Encoding UTF8 `
        -ErrorAction Stop
}
else {
    $Header = '"Host","User","Date","Service","Scope","Key","Identity","Rights","Signal","Inherited","RunAs","ImagePath","ServiceType"'

    $Header | Set-Content `
        -LiteralPath $CsvPath `
        -Encoding UTF8 `
        -ErrorAction Stop
}

# Export errors CSV.
if ($script:ScanErrors.Count -gt 0) {
    $script:ScanErrors | Export-Csv `
        -LiteralPath $ErrorCsvPath `
        -NoTypeInformation `
        -Encoding UTF8 `
        -ErrorAction Stop
}
else {
    $ErrorHeader = '"Host","User","Date","Service","Key","Operation","Error","ErrorId"'

    $ErrorHeader | Set-Content `
        -LiteralPath $ErrorCsvPath `
        -Encoding UTF8 `
        -ErrorAction Stop
}

# Calculate totals.
$Modify = @(
    $SortedResults | Where-Object {
        $_.Signal -eq 'Modify'
    }
)

$SubkeyOnly = @(
    $SortedResults | Where-Object {
        $_.Signal -eq 'Subkey-only'
    }
)

$Coverage = 0

if ($script:TotalKeys -gt 0) {
    $Coverage = [math]::Round(
        ($script:ReadableKeys / $script:TotalKeys) * 100,
        2
    )
}

# Console summary.
Write-Host ''
Write-Host '========== SERVICE REGISTRY ACL AUDIT =========='
Write-Host ''
Write-Host "Host:             $env:COMPUTERNAME"
Write-Host "User:             $($Me.Name)"
Write-Host "Date:             $ScanDate"
Write-Host ''
Write-Host "Services found:   $($Services.Count)"
Write-Host "Drivers skipped:  $script:SkippedDrivers"
Write-Host "ACLs attempted:   $script:TotalKeys"
Write-Host "ACLs readable:    $script:ReadableKeys"
Write-Host "ACLs unreadable:  $script:UnreadableKeys"
Write-Host "ACL read success: $Coverage%"
Write-Host "Total errors:     $($script:ScanErrors.Count)"
Write-Host ''
Write-Host "Total findings:   $($SortedResults.Count)"
Write-Host "Modify:           $($Modify.Count)"
Write-Host "Subkey-only:      $($SubkeyOnly.Count)"
Write-Host ''

# Determine assessment outcome.
if ($SortedResults.Count -gt 0) {

    Write-Host 'RESULT: Potentially writable service registry keys identified.' `
        -ForegroundColor Yellow
}
elseif (
    $script:ScanErrors.Count -gt 0 -or
    $script:TotalKeys -eq 0
) {

    Write-Host 'RESULT: INCONCLUSIVE - enumeration incomplete.' `
        -ForegroundColor Yellow
}
else {

    Write-Host 'RESULT: No matching writable service registry ACL entries found.' `
        -ForegroundColor Green
}

if ($script:ScanErrors.Count -gt 0) {

    Write-Host ''
    Write-Host '========== ERROR SUMMARY =========='

    $script:ScanErrors |
        Group-Object Operation, Error |
        Sort-Object Count -Descending |
        Select-Object Count, Name |
        Format-Table -AutoSize -Wrap

    Write-Warning 'Assessment coverage is incomplete.'
}

Write-Host ''
Write-Host "Findings CSV: $CsvPath" -ForegroundColor Cyan
Write-Host "Errors CSV:   $ErrorCsvPath" -ForegroundColor Cyan
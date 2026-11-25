$RootPath = 'SYSTEM\CurrentControlSet\Services'
$OutputDir = (Get-Location).Path

$CsvPath = Join-Path $OutputDir "$($env:COMPUTERNAME)_ServiceRegistryPermissions.csv"
$ErrorCsvPath = Join-Path $OutputDir "$($env:COMPUTERNAME)_ServiceRegistryErrors.csv"
$ScanDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

$DebugMode = $false

# Write-class registry permissions.
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

# Obtain current user identity and group SIDs.
$Me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$MySids = New-Object 'System.Collections.Generic.HashSet[string]'

[void]$MySids.Add($Me.User.Value)

foreach ($Group in $Me.Groups) {
    [void]$MySids.Add($Group.Value)
}

# Warn if running elevated.
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
$ServiceNames = @()

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

    Write-Warning "$Operation failed: $KeyPath"
    Write-Warning $ErrorRecord.Exception.Message
}

# Inspect ACL using native .NET registry API.
function Test-ServiceRegistryKey {
    param(
        [Microsoft.Win32.RegistryKey]$Key,
        [string]$ServiceName,
        [string]$Scope,
        [string]$RunAs,
        [string]$ImagePath,
        [string]$ServiceType
    )

    $script:TotalKeys++
    $KeyPath = $Key.Name

    try {
        $Acl = $Key.GetAccessControl(
            [System.Security.AccessControl.AccessControlSections]::Access
        )

        $Aces = $Acl.GetAccessRules(
            $true,
            $true,
            [System.Security.Principal.SecurityIdentifier]
        )

        $script:ReadableKeys++

        if ($DebugMode) {
            Write-Host "OK: $KeyPath" -ForegroundColor Green
        }
    }
    catch {
        $script:UnreadableKeys++

        Add-ScanError `
            -KeyPath $KeyPath `
            -ServiceName $ServiceName `
            -Operation 'Read ACL' `
            -ErrorRecord $_

        return
    }

    foreach ($Ace in $Aces) {

        # Only inspect Allow ACEs.
        if ($Ace.AccessControlType -ne 'Allow') {
            continue
        }

        # Ignore inheritance-only ACEs.
        if ($Ace.PropagationFlags -band
            [System.Security.AccessControl.PropagationFlags]::InheritOnly) {
            continue
        }

        $Sid = $Ace.IdentityReference.Value

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

        # Resolve SID to a readable account name.
        try {
            $Identity = $Ace.IdentityReference.Translate(
                [System.Security.Principal.NTAccount]
            ).Value
        }
        catch {
            $Identity = $Sid
        }

        # Classify permissions.
        if ($Mask -band $ModifyMask) {
            $Signal = 'Modify'
        }
        else {
            $Signal = 'Subkey-only'
        }

        $MatchedRights = ($Matched -join ', ')

        $Finding = [PSCustomObject][ordered]@{
            Host        = $env:COMPUTERNAME
            User        = $Me.Name
            Date        = $ScanDate
            Service     = $ServiceName
            Scope       = $Scope
            Key         = $KeyPath
            Identity    = $Identity
            SID         = $Sid
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

# Open Services registry root in read-only mode.
$Root = $null

try {
    $Root = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        $RootPath,
        $false
    )

    if ($null -eq $Root) {
        throw 'Unable to open Services registry root.'
    }

    $ServiceNames = @($Root.GetSubKeyNames())

    Write-Host "Discovered $($ServiceNames.Count) service keys."

    foreach ($ServiceName in $ServiceNames) {

        $Svc = $null
        $ServicePath = "$RootPath\$ServiceName"

        try {
            # Open service key read-only.
            $Svc = $Root.OpenSubKey($ServiceName, $false)

            if ($null -eq $Svc) {
                throw 'Unable to open service registry key.'
            }

            # Read optional registry values.
            $ImagePath = $Svc.GetValue('ImagePath', $null)
            $ServiceType = $Svc.GetValue('Type', $null)
            $RunAs = $Svc.GetValue('ObjectName', $null)

            # Skip known driver service types.
            if ($null -ne $ServiceType) {
                if ([int]$ServiceType -band 0x0F) {
                    $script:SkippedDrivers++
                    continue
                }
            }

            if (-not $ImagePath) {
                $ImagePath = 'Not configured'
            }

            if (-not $RunAs) {
                $RunAs = 'Unknown'
            }

            if ($null -eq $ServiceType) {
                $ServiceType = 'Unknown'
            }

            # Inspect service root ACL.
            Test-ServiceRegistryKey `
                -Key $Svc `
                -ServiceName $ServiceName `
                -Scope 'Root' `
                -RunAs $RunAs `
                -ImagePath $ImagePath `
                -ServiceType $ServiceType

            # Enumerate immediate service subkeys.
            $SubNames = @()

            try {
                $SubNames = @($Svc.GetSubKeyNames())
            }
            catch {
                Add-ScanError `
                    -KeyPath $ServicePath `
                    -ServiceName $ServiceName `
                    -Operation 'Enumerate subkeys' `
                    -ErrorRecord $_
            }

            foreach ($SubName in $SubNames) {

                $Sub = $null
                $SubPath = "$ServicePath\$SubName"

                try {
                    $Sub = $Svc.OpenSubKey($SubName, $false)

                    if ($null -eq $Sub) {
                        throw 'Unable to open registry subkey.'
                    }

                    Test-ServiceRegistryKey `
                        -Key $Sub `
                        -ServiceName $ServiceName `
                        -Scope 'Subkey' `
                        -RunAs $RunAs `
                        -ImagePath $ImagePath `
                        -ServiceType $ServiceType
                }
                catch {
                    Add-ScanError `
                        -KeyPath $SubPath `
                        -ServiceName $ServiceName `
                        -Operation 'Inspect subkey' `
                        -ErrorRecord $_
                }
                finally {
                    if ($null -ne $Sub) {
                        $Sub.Close()
                    }
                }
            }
        }
        catch {
            Add-ScanError `
                -KeyPath $ServicePath `
                -ServiceName $ServiceName `
                -Operation 'Inspect service' `
                -ErrorRecord $_
        }
        finally {
            if ($null -ne $Svc) {
                $Svc.Close()
            }
        }
    }
}
catch {
    Add-ScanError `
        -KeyPath $RootPath `
        -ServiceName 'N/A' `
        -Operation 'Enumerate services' `
        -ErrorRecord $_
}
finally {
    if ($null -ne $Root) {
        $Root.Close()
    }
}

# Sort findings.
$SortedResults = @(
    $script:Results | Sort-Object Signal, Scope, Service
)

# Export findings.
if ($SortedResults.Count -gt 0) {

    $SortedResults | Export-Csv `
        -LiteralPath $CsvPath `
        -NoTypeInformation `
        -Encoding UTF8 `
        -ErrorAction Stop
}
else {
    $Header = '"Host","User","Date","Service","Scope","Key","Identity","SID","Rights","Signal","Inherited","RunAs","ImagePath","ServiceType"'

    $Header | Set-Content `
        -LiteralPath $CsvPath `
        -Encoding UTF8 `
        -ErrorAction Stop
}

# Export errors.
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

# Calculate findings.
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

# Display summary.
Write-Host ''
Write-Host '========== SERVICE REGISTRY ACL AUDIT =========='
Write-Host ''
Write-Host "Host:             $env:COMPUTERNAME"
Write-Host "User:             $($Me.Name)"
Write-Host "Date:             $ScanDate"
Write-Host ''
Write-Host "Services found:   $($ServiceNames.Count)"
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
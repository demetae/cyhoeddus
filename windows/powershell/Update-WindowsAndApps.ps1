<#
.SYNOPSIS
    Windows + application maintenance (v6).

.DESCRIPTION
    - Applications: WinGet (via Microsoft.WinGet.Client for inventory).
    - Windows updates and drivers/firmware: Windows Update Agent (WUA) API.
    - Never requests or schedules a restart.

    NOTE: Updates installed through the WUA API may not appear in Settings >
    Windows Update history the same way as orchestrator-driven installs, and
    can conflict with an install the Windows Update orchestrator is running.
    The API is supported; just be aware of the difference.

    -ScanOnly is read-only with respect to the system: no module/NuGet
    install, no WinGet source refresh, no installs. (Log files are still
    written.) If Microsoft.WinGet.Client is missing, the app scan is skipped.

.NOTES
    Exit codes:
      0     no hard failures and no run-caused restart (Deferred/Unverified/
            Skipped items are listed in the summary but do not change the code)
      1     failures, partial installs, unexpected installer restarts
            (Attention), or section/run errors
      3010  this run installed/staged something that needs a restart
            (a restart that was already pending before the run does not count)
    Failures take priority over 3010.
#>
#requires -Version 5.1
#requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$ScanOnly,
    [switch]$NoBootstrap,
    [switch]$IncludeUnknownVersions,
    [switch]$IncludeFeatureUpdates,
    [string[]]$AdditionalExcludedIds = @(),
    [string]$LogRoot,
    [ValidateRange(1, 1000)]
    [int]$KeepLogs = 30
)

$ErrorActionPreference = 'Stop'

# ----------------------------------------------------------------- state ---
$script:Started       = Get-Date
$script:Rows          = New-Object 'System.Collections.Generic.List[object]'
$script:Remaining     = New-Object 'System.Collections.Generic.List[object]'
$script:Notes         = New-Object 'System.Collections.Generic.List[string]'
$script:Problems      = New-Object 'System.Collections.Generic.List[string]'
$script:PendingBefore = @()
$script:PendingAfter  = @()
$script:TranscriptStarted = $false
$script:TranscriptPath    = $null
$script:ScanOK        = @{ Apps = $false; Windows = $false; Drivers = $false }
$script:WingetPath    = $null
$script:SquirrelNames = @()

$script:ExcludedIds = @('Discord.*', 'SlackTechnologies.*', 'Squirrel.*') +
    $AdditionalExcludedIds

$script:HardwarePatterns = @(
    'Nvidia.*Driver*', 'AMD.*Driver*', 'Intel.*Driver*',
    'Dell.CommandUpdate*', 'Dell.SupportAssist*',
    'Lenovo.SystemUpdate*', 'Lenovo.Updating*',
    'HP.ImageAssistant*', 'HP.SupportAssistant*',
    'Intel.DriverAndSupportAssistant*', 'ASUS.ArmouryCrate*'
)

# WinGet return codes (microsoft/winget-cli doc/windows/package-manager/winget/returnCodes.md)
$script:WingetKinds = @{
    '0x8A15002B' = 'NoApplicable'     # update not applicable
    '0x8A150101' = 'InUse'            # package in use
    '0x8A150102' = 'Busy'             # another installation in progress
    '0x8A150103' = 'InUse'            # file in use
    '0x8A150109' = 'RebootToFinish'   # installed; restart needed to finish
    '0x8A15010A' = 'RebootFirst'      # failed; restart needed before install
    '0x8A15010B' = 'RebootInitiated'  # installer started a restart
    '0x8A150111' = 'InUse'            # package in use by another application
}

# --------------------------------------------------------------- helpers ---
function Write-Section {
    param([Parameter(Mandatory)][string]$Text)
    $bar = '=' * 64
    Write-Host ''
    Write-Host $bar -ForegroundColor Cyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host $bar -ForegroundColor Cyan
}

function Add-Note {
    param([Parameter(Mandatory)][string]$Text)
    if (-not [string]::IsNullOrWhiteSpace($Text)) {
        $script:Notes.Add($Text)
        Write-Host ('  NOTE: {0}' -f $Text) -ForegroundColor Yellow
    }
}

function Add-Problem {
    param([Parameter(Mandatory)][string]$Text)
    if (-not [string]::IsNullOrWhiteSpace($Text)) {
        $script:Problems.Add($Text)
        Add-Note -Text $Text
    }
}

function Get-SafeProperty {
    param($Object, [Parameter(Mandatory)][string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    try {
        $p = $Object.PSObject.Properties[$Name]
        if ($null -ne $p) { return $p.Value }
    }
    catch { }
    return $Default
}

function New-Result {
    param(
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$Name,
        [string]$Id = '',
        [string]$Source = ''
    )
    $row = [pscustomobject][ordered]@{
        Area = $Area; Name = $Name; Id = $Id; Source = $Source
        Before = ''; Target = ''; After = ''
        Outcome = 'Not attempted'; RebootRequired = $false; RebootCausedByRun = $false
        Code = ''; Detail = ''
    }
    $script:Rows.Add($row)
    return $row
}

function ConvertTo-HexCode {
    param([Parameter(Mandatory)][long]$Code)
    return ('0x{0:X8}' -f ($Code -band [long]4294967295))
}

function Get-RebootSignals {
    $found = New-Object 'System.Collections.Generic.List[string]'

    $keys = @{
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' =
            'Component Based Servicing: restart pending'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' =
            'Windows Update: restart required'
    }
    foreach ($k in $keys.Keys) {
        if (Test-Path -LiteralPath $k) { $found.Add($keys[$k]) }
    }

    try {
        $sm = Get-ItemProperty -ErrorAction SilentlyContinue `
            -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        foreach ($n in 'PendingFileRenameOperations', 'PendingFileRenameOperations2') {
            $v = @(Get-SafeProperty -Object $sm -Name $n -Default @()) |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
            if (@($v).Count -gt 0) {
                $found.Add(('Pending file operations ({0}); restart may be needed' -f $n))
            }
        }
    }
    catch { }

    try {
        $si = New-Object -ComObject Microsoft.Update.SystemInfo
        if ($si.RebootRequired) { $found.Add('Windows Update Agent: restart required') }
    }
    catch {
        Add-Note -Text ('Windows Update reboot-status query failed: {0}' -f $_.Exception.Message)
    }

    return $found.ToArray()
}

function Remove-OldLogs {
    # Runs before the new transcript starts, so the current log can never be touched.
    try {
        Get-ChildItem -LiteralPath $LogRoot -Filter 'WindowsUpdate_*.log' -File |
            Sort-Object LastWriteTime -Descending |
            Select-Object -Skip ($KeepLogs - 1) |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning ('Log retention failed: {0}' -f $_.Exception.Message)
    }
}

# ---------------------------------------------------------------- WinGet ---
function Initialize-WinGetModule {
    if (Get-Module -ListAvailable -Name Microsoft.WinGet.Client) {
        Import-Module Microsoft.WinGet.Client -ErrorAction Stop
        return $true
    }

    if ($ScanOnly) {
        Add-Note -Text ('Microsoft.WinGet.Client is not installed; application scan skipped ' +
            '(-ScanOnly never installs modules).')
        return $false
    }
    if ($NoBootstrap) {
        Add-Problem -Text 'Microsoft.WinGet.Client is missing and -NoBootstrap was specified; application section skipped.'
        return $false
    }

    Write-Host '  Installing Microsoft.WinGet.Client from PSGallery...' -ForegroundColor Yellow
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    if (-not (Get-Command -Name Install-Module -ErrorAction SilentlyContinue)) {
        throw 'Install-Module is unavailable; cannot install Microsoft.WinGet.Client.'
    }

    if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
        $nuget = @{
            Name = 'NuGet'; MinimumVersion = '2.8.5.201'
            Scope = 'CurrentUser'; Force = $true; Confirm = $false
        }
        Install-PackageProvider @nuget | Out-Null
    }

    $gallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
    if (-not $gallery) {
        Register-PSRepository -Default
        $gallery = Get-PSRepository -Name PSGallery -ErrorAction Stop
    }
    if ([string]$gallery.SourceLocation -notmatch '^https://www\.powershellgallery\.com/api/v2/?$') {
        throw 'PSGallery has an unexpected source URL; automatic module installation refused.'
    }

    $mod = @{
        Name = 'Microsoft.WinGet.Client'; Repository = 'PSGallery'
        Scope = 'CurrentUser'; Force = $true; Confirm = $false; ErrorAction = 'Stop'
    }
    Install-Module @mod
    Add-Note -Text 'Installed prerequisite module: Microsoft.WinGet.Client.'

    Import-Module Microsoft.WinGet.Client -ErrorAction Stop
    return $true
}

function Invoke-WinGet {
    param([Parameter(Mandatory)][string[]]$Arguments, [switch]$Quiet)

    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $lines = New-Object 'System.Collections.Generic.List[string]'
        $global:LASTEXITCODE = $null
        if (-not $Quiet) {
            Write-Host ('  > winget {0}' -f ($Arguments -join ' ')) -ForegroundColor DarkGray
        }

        & $script:WingetPath @Arguments 2>&1 | ForEach-Object {
            $line = [string]$_
            $lines.Add($line)
            if (-not $Quiet) { Write-Host $line }
        }

        $exit = $global:LASTEXITCODE
        if ($null -eq $exit) { throw 'WinGet did not return a process exit code.' }

        return [pscustomobject]@{
            Code  = [int]$exit
            Hex   = (ConvertTo-HexCode -Code $exit)
            Lines = $lines.ToArray()
        }
    }
    finally { $ErrorActionPreference = $old }
}

function Get-WinGetKind {
    # Exit code first; English text matching is only a fallback for unknown codes.
    param([Parameter(Mandatory)]$Result)

    if ($Result.Code -eq 0) { return 'Success' }
    if ($script:WingetKinds.ContainsKey($Result.Hex)) { return $script:WingetKinds[$Result.Hex] }

    $text = $Result.Lines -join "`n"
    if ($text -match '(?i)currently running|exit the application then try again|application.*in use') {
        return 'InUse'
    }
    return 'Other'
}

function ConvertTo-AppRecord {
    param([Parameter(Mandatory)]$Package)
    [pscustomobject]@{
        Name              = [string](Get-SafeProperty -Object $Package -Name 'Name' -Default '')
        Id                = [string](Get-SafeProperty -Object $Package -Name 'Id' -Default '')
        Source            = [string](Get-SafeProperty -Object $Package -Name 'Source' -Default '')
        InstalledVersion  = [string](Get-SafeProperty -Object $Package -Name 'InstalledVersion' -Default '')
        AvailableVersions = @(Get-SafeProperty -Object $Package -Name 'AvailableVersions' -Default @())
        IsUpdateAvailable = [bool](Get-SafeProperty -Object $Package -Name 'IsUpdateAvailable' -Default $false)
    }
}

function Get-AppSnapshot {
    foreach ($p in @(Microsoft.WinGet.Client\Get-WinGetPackage -ErrorAction Stop)) {
        ConvertTo-AppRecord -Package $p
    }
}

function Get-AppState {
    # Targeted lookup; falls back to the full inventory only if the targeted call errors.
    param([Parameter(Mandatory)][string]$Id)
    try {
        $p = @(Microsoft.WinGet.Client\Get-WinGetPackage -Id $Id -MatchOption Equals -ErrorAction Stop) |
            Where-Object { $_.Id -eq $Id } | Select-Object -First 1
        if ($p) { return (ConvertTo-AppRecord -Package $p) }
        return $null
    }
    catch {
        return (@(Get-AppSnapshot) | Where-Object { $_.Id -eq $Id } | Select-Object -First 1)
    }
}

function Get-AppTargetVersion {
    param($Package)
    if ($null -eq $Package) { return '' }
    $v = @($Package.AvailableVersions | ForEach-Object { [string]$_ } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($v.Count -gt 0) { return $v[0] }
    return ''
}

function Normalize-AppName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    $clean = $Name -replace '(?i)\s*\((?:x64|x86|64-bit|32-bit|user|machine)\)\s*$', ''
    return ($clean.ToLowerInvariant() -replace '[^\p{L}\p{Nd}]', '')
}

function Get-SquirrelInstalledNames {
    $names = New-Object 'System.Collections.Generic.List[string]'
    $roots = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            try {
                $e = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
                $display = [string](Get-SafeProperty -Object $e -Name 'DisplayName' -Default '')
                $uninst  = '{0} {1}' -f
                    [string](Get-SafeProperty -Object $e -Name 'UninstallString' -Default ''),
                    [string](Get-SafeProperty -Object $e -Name 'QuietUninstallString' -Default '')
                $aware   = Get-SafeProperty -Object $e -Name 'SquirrelAwareVersion'

                if ($display -and
                    ($uninst -match '(?i)squirrel|update\.exe.*--uninstall' -or $null -ne $aware)) {
                    $n = Normalize-AppName -Name $display
                    if ($n -and -not $names.Contains($n)) { $names.Add($n) }
                }
            }
            catch { }
        }
    }
    return $names.ToArray()
}

function Get-AppExclusionReason {
    param([string]$Id, [string]$Name)

    foreach ($pattern in $script:ExcludedIds) {
        if ($Id -like $pattern) { return ('Explicit exclusion: {0}' -f $pattern) }
    }
    $combined = '{0} {1}' -f $Id, $Name
    if ($combined -match '(?i)\b(discord|slack|squirrel)\b') {
        return 'Discord / Slack / Squirrel exclusion'
    }
    foreach ($pattern in $script:HardwarePatterns) {
        if ($Id -like $pattern) {
            return 'Driver/firmware/OEM maintenance package: Windows Update route only'
        }
    }
    if ($combined -match '(?i)\b(drivers?|firmware|bios|uefi)\b') {
        return 'Hardware-related package: Windows Update route only'
    }
    $normal = Normalize-AppName -Name $Name
    foreach ($sq in $script:SquirrelNames) {
        if ($normal.Length -ge 4 -and $sq.Length -ge 4 -and
            ($normal.Contains($sq) -or $sq.Contains($normal))) {
            return 'Squirrel-style installed application (registry detection)'
        }
    }
    return ''
}

function Invoke-OneAppUpgrade {
    param([Parameter(Mandatory)]$Row, [Parameter(Mandatory)]$Package)

    $id = $Row.Id
    $wingetArgs = @(
        'upgrade', '--id', $id, '--exact', '--source', $Row.Source,
        '--silent', '--accept-package-agreements', '--accept-source-agreements',
        '--disable-interactivity'
    )
    if ($IncludeUnknownVersions) { $wingetArgs += '--include-unknown' }

    $result = Invoke-WinGet -Arguments $wingetArgs
    $kind   = Get-WinGetKind -Result $result

    # "Not applicable" while WinGet still advertises an update: retry once.
    if ($kind -eq 'NoApplicable') {
        try {
            $state = Get-AppState -Id $id
            if ($state -and $state.IsUpdateAvailable) {
                Write-Host ('  WinGet still advertises an update for {0}; retrying once...' -f $Row.Name) -ForegroundColor Yellow
                Start-Sleep -Seconds 1
                $result = Invoke-WinGet -Arguments $wingetArgs
                $kind   = Get-WinGetKind -Result $result
            }
        }
        catch {
            Add-Note -Text ('Could not verify retry state for {0}: {1}' -f $Row.Name, $_.Exception.Message)
        }
    }

    $Row.Code = $result.Hex

    if ($kind -in @('InUse', 'Busy')) {
        $Row.Outcome = 'Deferred'
        if ($kind -eq 'Busy') {
            $Row.Detail = 'Another installation is in progress. Run the updater again later.'
        }
        else {
            $Row.Detail = 'Application or file is in use. Close it and run the updater again.'
        }
        return
    }

    if ($kind -eq 'RebootFirst') {
        # Nothing was installed: a restart is needed, but this run did not cause it
        # (RebootCausedByRun stays false), so it must not produce exit code 3010.
        $Row.Outcome = 'Deferred'
        $Row.RebootRequired = $true
        $Row.Detail = 'Installation failed: a restart is required first. Restart, then run the updater again.'
        return
    }

    if ($kind -eq 'RebootInitiated') {
        $Row.Outcome = 'Attention'
        $Row.RebootRequired = $true
        $Row.RebootCausedByRun = $true
        $Row.Detail = 'The installer initiated a restart. Installation state is not verified.'
        try {
            & shutdown.exe /a 2>&1 | Out-Null
            Add-Note -Text ('{0}: installer started a restart; "shutdown /a" attempted (exit {1}) as best effort. ' -f
                $Row.Name, $LASTEXITCODE) 
            Add-Note -Text 'The abort is not relied on; the installation may be incomplete. Restart and re-run.'
        }
        catch {
            Add-Note -Text ('{0}: installer started a restart; abort attempt failed: {1}' -f
                $Row.Name, $_.Exception.Message)
        }
        return
    }

    # Verify installed version (targeted lookup).
    Start-Sleep -Milliseconds 500
    try {
        $after = Get-AppState -Id $id
        if ($after) { $Row.After = [string]$after.InstalledVersion }
    }
    catch {
        Add-Note -Text ('Post-update version verification failed for {0}: {1}' -f $Row.Name, $_.Exception.Message)
    }

    if ($kind -eq 'RebootToFinish') {
        # The WinGet result is authoritative; the installed version may not change until restart.
        $Row.Outcome = 'Updated'
        $Row.RebootRequired = $true
        $Row.RebootCausedByRun = $true
        $Row.Detail = 'Installed; a restart is required to finish. Version may not change until restart.'
        return
    }

    if ($Row.After -and $Row.Before -and $Row.After -ne $Row.Before) {
        $Row.Outcome = 'Updated'
        $Row.Detail  = 'Installed-version change verified.'
    }
    elseif ($kind -eq 'Success') {
        $Row.Outcome = 'Unverified'
        $Row.Detail  = 'WinGet reported success, but an installed-version change could not be verified.'
    }
    elseif ($kind -eq 'NoApplicable') {
        $Row.Outcome = 'No change'
        $Row.Detail  = 'WinGet found no applicable upgrade.'
    }
    else {
        $Row.Outcome = 'Failed'
        $Row.Detail  = 'WinGet upgrade failed. Review transcript output.'
    }
}

function Invoke-AppUpdates {
    Write-Section -Text 'APPLICATIONS - WINGET'

    if (-not (Initialize-WinGetModule)) { return }

    if (-not $ScanOnly) {
        $script:WingetPath = (Get-Command -Name winget.exe -CommandType Application -ErrorAction Stop |
            Select-Object -First 1).Source

        $ver = Invoke-WinGet -Arguments @('--version')
        if ($ver.Code -ne 0) { throw ('winget --version failed: {0}' -f $ver.Hex) }

        $refresh = Invoke-WinGet -Arguments @('source', 'update', '--disable-interactivity')
        if ($refresh.Code -ne 0) { Add-Note -Text 'One or more WinGet sources failed to refresh.' }
    }

    $script:SquirrelNames = @(Get-SquirrelInstalledNames)
    $before = @(Get-AppSnapshot)
    $script:ScanOK.Apps = $true

    foreach ($pkg in @($before | Where-Object { $_.IsUpdateAvailable })) {
        $source = $pkg.Source
        if ([string]::IsNullOrWhiteSpace($source)) { $source = 'winget' }

        $row = New-Result -Area 'Application' -Name $pkg.Name -Id $pkg.Id -Source $source
        $row.Before = $pkg.InstalledVersion
        $row.Target = Get-AppTargetVersion -Package $pkg

        $reason = Get-AppExclusionReason -Id $pkg.Id -Name $pkg.Name
        if ($reason) {
            $row.Outcome = 'Skipped'
            $row.Detail  = $reason
            continue
        }

        if (-not $IncludeUnknownVersions -and
            ([string]::IsNullOrWhiteSpace($row.Before) -or $row.Before -eq 'Unknown')) {
            $row.Outcome = 'Skipped'
            $row.Detail  = 'Installed version is unknown; use -IncludeUnknownVersions to opt in.'
            continue
        }

        if ($ScanOnly) {
            $row.Outcome = 'Available'
            $row.Detail  = 'Upgrade available; scan-only mode.'
            continue
        }

        Invoke-OneAppUpgrade -Row $row -Package $pkg
    }

    if ($ScanOnly) { return }

    try {
        foreach ($pkg in @(Get-AppSnapshot | Where-Object { $_.IsUpdateAvailable })) {
            $script:Remaining.Add([pscustomobject]@{
                Area = 'Application'; Name = $pkg.Name; Id = $pkg.Id
                Detail = 'Still advertised by WinGet'
            })
        }
    }
    catch {
        Add-Note -Text ('Final WinGet inventory failed: {0}' -f $_.Exception.Message)
    }
}

# ------------------------------------------------------- Windows Update ---
function Search-WuaUpdates {
    param([Parameter(Mandatory)][ValidateSet('Software', 'Driver')][string]$Type)

    $session = New-Object -ComObject Microsoft.Update.Session
    try { $session.ClientApplicationID = 'Windows + Application Maintenance Script' } catch { }

    $searcher = $session.CreateUpdateSearcher()
    $searcher.ServerSelection = 0

    $found = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='$Type'")
    $list  = New-Object 'System.Collections.Generic.List[object]'
    for ($i = 0; $i -lt $found.Updates.Count; $i++) { $list.Add($found.Updates.Item($i)) }

    return [pscustomobject]@{ Session = $session; Updates = $list.ToArray() }
}

function Get-WuaTitle {
    param($Update)
    $t = ''
    try { $t = [string]$Update.Title } catch { }
    if ([string]::IsNullOrWhiteSpace($t)) { return 'Unnamed update' }
    return $t
}

function Get-WuaUpdateId {
    param($Update)
    try { return [string]$Update.Identity.UpdateID } catch { return '' }
}

function Get-WuaKbText {
    param($Update)
    $ids = New-Object 'System.Collections.Generic.List[string]'
    try {
        for ($i = 0; $i -lt $Update.KBArticleIDs.Count; $i++) {
            $v = [string]$Update.KBArticleIDs.Item($i)
            if ($v) { $ids.Add("KB$v") }
        }
    }
    catch { }
    return ($ids.ToArray() -join ', ')
}

function Test-WuaFeatureUpdate {
    param($Update)
    $upgradeCategory = '3689bdc8-b205-4af4-8d4a-a63924c5e9d5'
    try {
        for ($i = 0; $i -lt $Update.Categories.Count; $i++) {
            if ([string]$Update.Categories.Item($i).CategoryID -eq $upgradeCategory) { return $true }
        }
    }
    catch { }
    return ((Get-WuaTitle -Update $Update) -match '(?i)\bfeature update\b|\bupgrade to Windows\b')
}

function Test-WuaFirmware {
    param($Update)
    $class = ''
    try { $class = [string]$Update.DriverClass } catch { }
    if ($class -match '(?i)^firmware$') { return $true }
    return ((Get-WuaTitle -Update $Update) -match '(?i)\b(firmware|bios|uefi)\b')
}

function Test-AcPower {
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $s = [string][System.Windows.Forms.SystemInformation]::PowerStatus.PowerLineStatus
        return [pscustomobject]@{ Known = $true; Online = ($s -eq 'Online'); Text = $s }
    }
    catch {
        return [pscustomobject]@{ Known = $false; Online = $false; Text = 'Unknown' }
    }
}

function Invoke-WuaInstall {
    param(
        [Parameter(Mandatory)]$Session,
        [Parameter(Mandatory)]$Update,
        [Parameter(Mandatory)]$Row,
        [switch]$Firmware
    )

    $coll = New-Object -ComObject Microsoft.Update.UpdateColl
    [void]$coll.Add($Update)

    try {
        if (-not [bool]$Update.EulaAccepted) { $Update.AcceptEula() }
    }
    catch {
        $Row.Outcome = 'Failed'
        $Row.Detail  = ('Could not accept update EULA: {0}' -f $_.Exception.Message)
        return
    }

    Write-Host ''
    Write-Host ('  Downloading: {0}' -f $Row.Name) -ForegroundColor Yellow
    try {
        $dl = $Session.CreateUpdateDownloader()
        $dl.Updates = $coll
        $code = [int]$dl.Download().ResultCode

        if ($code -notin @(2, 3)) {
            if ($code -eq 5) { $Row.Outcome = 'Deferred' } else { $Row.Outcome = 'Failed' }
            $Row.Detail = ('Windows Update download returned ResultCode={0}' -f $code)
            return
        }
        if ($code -eq 3) {
            Add-Note -Text ('Download completed with errors for {0}; installation will still be attempted.' -f $Row.Name)
        }
    }
    catch {
        $Row.Outcome = 'Failed'
        $Row.Detail  = ('Windows Update download failed: {0}' -f $_.Exception.Message)
        return
    }

    Write-Host ('  Installing: {0}' -f $Row.Name) -ForegroundColor Yellow
    try {
        $inst = $Session.CreateUpdateInstaller()
        $inst.Updates = $coll
        try { $inst.AllowSourcePrompts = $false } catch { }
        try { $inst.ForceQuiet = $true } catch { }

        $res  = $inst.Install()
        $item = $res.GetUpdateResult(0)
        $Row.Code = ConvertTo-HexCode -Code ([long]$item.HResult)
        $Row.RebootRequired = [bool]$res.RebootRequired
        $Row.RebootCausedByRun = ($Row.RebootRequired -and ([int]$item.ResultCode -in @(2, 3)))

        switch ([int]$item.ResultCode) {
            2 {
                if ($Firmware) {
                    $Row.Outcome = 'Staged'
                    $Row.Detail  = 'Firmware installed/staged. Activation and version are not verified until restart.'
                }
                else {
                    $Row.Outcome = 'Installed'
                    $Row.Detail  = 'Windows Update Agent reports successful installation.'
                }
            }
            3 { $Row.Outcome = 'Partial';  $Row.Detail = 'Installation completed with errors.' }
            4 { $Row.Outcome = 'Failed';   $Row.Detail = 'Windows Update Agent reports installation failure.' }
            5 { $Row.Outcome = 'Deferred'; $Row.Detail = 'Windows Update Agent reports installation aborted.' }
            default {
                $Row.Outcome = 'Unverified'
                $Row.Detail  = ('Windows Update Agent returned ResultCode={0}' -f [int]$item.ResultCode)
            }
        }
    }
    catch {
        $Row.Outcome = 'Failed'
        $Row.Detail  = ('Windows Update installation failed: {0}' -f $_.Exception.Message)
    }
}

function Invoke-WindowsUpdatePass {
    param([Parameter(Mandatory)][ValidateSet('Software', 'Driver')][string]$Type)

    if ($Type -eq 'Software') {
        $area = 'Windows Update'; $heading = 'WINDOWS UPDATE'
    }
    else {
        $area = 'Driver / firmware'; $heading = 'DRIVERS / FIRMWARE - WINDOWS UPDATE'
    }
    Write-Section -Text $heading

    $search  = Search-WuaUpdates -Type $Type
    $updates = @($search.Updates)
    if ($Type -eq 'Software') { $script:ScanOK.Windows = $true } else { $script:ScanOK.Drivers = $true }

    Write-Host ('  Offered updates: {0}' -f $updates.Count) -ForegroundColor Cyan

    $haltDrivers = $false

    foreach ($u in $updates) {
        $id  = Get-WuaUpdateId -Update $u
        $row = New-Result -Area $area -Name (Get-WuaTitle -Update $u) -Id $id -Source 'Windows Update'
        $row.Target = Get-WuaKbText -Update $u

        if ([string]::IsNullOrWhiteSpace($id)) {
            $row.Outcome = 'Skipped'
            $row.Detail  = 'Windows Update Agent did not expose a reliable UpdateID.'
            continue
        }

        if ($Type -eq 'Software') {
            if (-not $IncludeFeatureUpdates -and (Test-WuaFeatureUpdate -Update $u)) {
                $row.Outcome = 'Skipped'
                $row.Detail  = 'Windows feature upgrade excluded by default. Use -IncludeFeatureUpdates to opt in.'
                continue
            }
            # Only software updates are skipped for possible user input; drivers proceed.
            $interactive = $false
            try { $interactive = [bool]$u.InstallationBehavior.CanRequestUserInput } catch { }
            if ($interactive) {
                $row.Outcome = 'Skipped'
                $row.Detail  = 'Software update can request interactive input; handle manually.'
                continue
            }
        }

        $isFirmware = ($Type -eq 'Driver') -and (Test-WuaFirmware -Update $u)
        if ($isFirmware) {
            $power = Test-AcPower
            if (-not $power.Known) {
                $row.Outcome = 'Deferred'
                $row.Detail  = 'Firmware deferred because AC power status could not be verified.'
                continue
            }
            if (-not $power.Online) {
                $row.Outcome = 'Deferred'
                $row.Detail  = ('Firmware deferred because AC power is not confirmed ({0}).' -f $power.Text)
                continue
            }
        }

        if ($ScanOnly) {
            $row.Outcome = 'Available'
            $row.Detail  = 'Offered by Windows Update; scan-only mode.'
            continue
        }

        if ($haltDrivers) {
            $row.Outcome = 'Deferred'
            $row.Detail  = 'Skipped: an earlier firmware update needs a restart. Restart, then run the updater again.'
            continue
        }

        Invoke-WuaInstall -Session $search.Session -Update $u -Row $row -Firmware:$isFirmware

        if ($Type -eq 'Driver' -and $isFirmware -and $row.RebootRequired) {
            $haltDrivers = $true
            Add-Note -Text ('Firmware update "{0}" needs a restart; remaining driver/firmware installs deferred.' -f $row.Name)
        }
    }

    if ($ScanOnly) { return }

    try {
        foreach ($u in @((Search-WuaUpdates -Type $Type).Updates)) {
            $script:Remaining.Add([pscustomobject]@{
                Area = $area; Name = (Get-WuaTitle -Update $u); Id = (Get-WuaUpdateId -Update $u)
                Detail = 'Still offered by Windows Update; may be excluded, failed, or awaiting restart.'
            })
        }
    }
    catch {
        Add-Problem -Text ('Final {0} scan failed: {1}' -f $area, $_.Exception.Message)
    }
}

# ------------------------------------------------------ summary / exit ---
function Get-ExitCode {
    $failed = @($script:Rows | Where-Object { $_.Outcome -in @('Failed', 'Partial', 'Attention') }).Count
    if ($failed -gt 0 -or $script:Problems.Count -gt 0) { return 1 }

    # Only restarts caused by this run count; pre-existing or retry-first restarts do not.
    if (@($script:Rows | Where-Object { $_.RebootCausedByRun }).Count -gt 0) { return 3010 }
    return 0
}

function Write-FinalSummary {
    $rows = $script:Rows.ToArray()

    function Count-Rows { param($Area, $Outcome)
        @($rows | Where-Object { $_.Area -eq $Area -and $_.Outcome -eq $Outcome }).Count
    }

    $skipped   = @($rows | Where-Object { $_.Outcome -eq 'Skipped' }).Count
    $attention = @($rows | Where-Object {
        $_.Outcome -in @('Failed', 'Partial', 'Unverified', 'Deferred', 'Attention', 'Not attempted')
    }).Count
    $runReboot = @($rows | Where-Object { $_.RebootCausedByRun })

    if ($ScanOnly) { $mode = 'SCAN ONLY' } else { $mode = 'UPDATE RUN' }

    Write-Section -Text 'FINAL SUMMARY'
    Write-Host ('Mode: {0} | Computer: {1} | Started: {2}' -f
        $mode, $env:COMPUTERNAME, $script:Started.ToString('yyyy-MM-dd HH:mm:ss'))
    Write-Host ('Elapsed: {0:hh\:mm\:ss}' -f ((Get-Date) - $script:Started))
    Write-Host ''
    Write-Host ('Applications with verified/reported updates : {0}' -f (Count-Rows 'Application' 'Updated'))
    Write-Host ('Windows updates reported installed          : {0}' -f (Count-Rows 'Windows Update' 'Installed'))
    Write-Host ('Driver packages reported installed          : {0}' -f (Count-Rows 'Driver / firmware' 'Installed'))
    Write-Host ('Firmware packages installed/staged          : {0}' -f (Count-Rows 'Driver / firmware' 'Staged'))
    Write-Host ('Deliberately skipped items                  : {0}' -f $skipped)
    Write-Host ('Items requiring attention                   : {0}' -f $attention)
    Write-Host ('Section / verification errors               : {0}' -f $script:Problems.Count)
    Write-Host ('Warnings / informational notes              : {0}' -f $script:Notes.Count)
    Write-Host ('Scans completed: apps={0}; Windows={1}; drivers={2}' -f
        $script:ScanOK.Apps, $script:ScanOK.Windows, $script:ScanOK.Drivers)

    Write-Host ''
    if ($runReboot.Count -gt 0) {
        Write-Host 'Restart status: RESTART REQUIRED - changes from this run need a restart' -ForegroundColor Yellow
        foreach ($r in $runReboot) { Write-Host ('  - {0}' -f $r.Name) }
    }
    elseif ($script:PendingAfter.Count -gt 0 -or @($rows | Where-Object { $_.RebootRequired }).Count -gt 0) {
        Write-Host 'Restart status: restart pending/needed before retry (not caused by a change made by this run)' -ForegroundColor Yellow
    }
    else {
        Write-Host 'Restart status: no pending-restart indicator detected (not a guarantee)' -ForegroundColor Cyan
    }
    foreach ($r in $script:PendingAfter) { Write-Host ('  - {0}' -f $r) }
    Write-Host 'This script did not request or schedule a restart. Windows restart policies are unchanged.'

    $colours = @{
        Updated = 'Green'; Installed = 'Green'; Staged = 'Green'
        Failed = 'Red'; Partial = 'Red'
        Skipped = 'Yellow'; Deferred = 'Yellow'; Unverified = 'Yellow'
        Attention = 'Yellow'; 'No change' = 'Yellow'; Available = 'Yellow'
    }

    foreach ($area in 'Application', 'Windows Update', 'Driver / firmware') {
        Write-Host ''
        Write-Host ('{0} RESULTS' -f $area.ToUpperInvariant())

        $items = @($rows | Where-Object { $_.Area -eq $area })
        if ($items.Count -eq 0) {
            $scanSucceeded = $false
            switch ($area) {
                'Application'       { $scanSucceeded = [bool]$script:ScanOK.Apps }
                'Windows Update'    { $scanSucceeded = [bool]$script:ScanOK.Windows }
                'Driver / firmware' { $scanSucceeded = [bool]$script:ScanOK.Drivers }
            }

            if ($scanSucceeded) {
                Write-Host '  Nothing offered.'
            }
            else {
                Write-Host ('  No item results. The scan did not complete or was skipped; ' +
                    'check notes/errors before assuming this area is up to date.')
            }
            continue
        }

        foreach ($row in $items) {
            $colour = 'Gray'
            if ($colours.ContainsKey($row.Outcome)) { $colour = $colours[$row.Outcome] }
            Write-Host ('  [{0}] {1}' -f $row.Outcome, $row.Name) -ForegroundColor $colour

            if ($row.Area -eq 'Application') {
                $after = 'not verified'
                if ($row.After) { $after = $row.After }
                Write-Host ('    Before: {0} | Target: {1} | After: {2}' -f $row.Before, $row.Target, $after)
            }
            elseif ($row.Target) {
                Write-Host ('    KB / reference: {0}' -f $row.Target)
            }
            if ($row.RebootRequired) { Write-Host '    Restart required' }
            if ($row.Detail)         { Write-Host ('    {0}' -f $row.Detail) }
            if ($row.Code)           { Write-Host ('    Code: {0}' -f $row.Code) }
        }
    }

    Write-Host ''
    Write-Host 'REMAINING OFFERS (may include deliberate exclusions or restart-staged updates)'
    if ($ScanOnly) {
        Write-Host '  See Available / Skipped results above; no updates were applied.'
    }
    elseif ($script:Remaining.Count -eq 0) {
        Write-Host '  No remaining offers were recorded. Failed scans are shown in notes.'
    }
    else {
        foreach ($item in $script:Remaining) { Write-Host ('  [{0}] {1}' -f $item.Area, $item.Name) }
    }

    Write-Host ''
    Write-Host 'NOTES / ERRORS'
    if ($script:Notes.Count -eq 0) { Write-Host '  None recorded.' }
    foreach ($n in $script:Notes) { Write-Host ('  - {0}' -f $n) }

    Write-Host ''
    Write-Host ('Exit code: {0} (0 no hard failures, 1 failures/attention/errors, 3010 restart required by this run)' -f (Get-ExitCode))
    Write-Host ('Transcript: {0}' -f $script:TranscriptPath) -ForegroundColor Cyan
}

# ------------------------------------------------------------------ main ---
try {
    if ($env:OS -ne 'Windows_NT') { throw 'This script must be run on Windows.' }
    if ($PSVersionTable.PSEdition -ne 'Desktop') {
        throw 'Run this script in Windows PowerShell 5.1 (powershell.exe), not PowerShell 7.'
    }
    if (-not [Environment]::Is64BitProcess) { throw 'Run this script in 64-bit Windows PowerShell.' }

    if ([string]::IsNullOrWhiteSpace($LogRoot)) {
        $docs = [Environment]::GetFolderPath('MyDocuments')
        if ([string]::IsNullOrWhiteSpace($docs)) { $docs = $env:TEMP }
        $LogRoot = Join-Path -Path $docs -ChildPath 'WindowsUpdateLogs'
    }
    New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null

    Remove-OldLogs

    $script:TranscriptPath = Join-Path -Path $LogRoot -ChildPath (
        'WindowsUpdate_{0}.log' -f (Get-Date -Format 'yyyy-MM-dd_HHmmss'))
    Start-Transcript -Path $script:TranscriptPath -Force | Out-Null
    $script:TranscriptStarted = $true

    Write-Section -Text 'WINDOWS + APPLICATION MAINTENANCE'
    Write-Host ('  Computer: {0} | User: {1}' -f
        $env:COMPUTERNAME, [Security.Principal.WindowsIdentity]::GetCurrent().Name)
    Write-Host ('  Scan only: {0} | Automatic reboot by this script: DISABLED' -f [bool]$ScanOnly) -ForegroundColor Green
    Write-Host ('  Transcript: {0}' -f $script:TranscriptPath) -ForegroundColor DarkCyan
    Write-Host '  Save work. Existing Windows policies and third-party behaviour remain outside this script.' -ForegroundColor Yellow

    $script:PendingBefore = @(Get-RebootSignals)
    if ($script:PendingBefore.Count -gt 0) {
        Add-Note -Text ('A restart was already pending before this run. ' +
            'Some updates may be deferred or fail until a manual restart.')
    }

    try { Invoke-AppUpdates }
    catch { Add-Problem -Text ('Application section could not complete: {0}' -f $_.Exception.Message) }

    try { Invoke-WindowsUpdatePass -Type Software }
    catch { Add-Problem -Text ('Windows Update section could not complete: {0}' -f $_.Exception.Message) }

    try { Invoke-WindowsUpdatePass -Type Driver }
    catch { Add-Problem -Text ('Driver / firmware section could not complete: {0}' -f $_.Exception.Message) }
}
catch {
    Add-Problem -Text ('Run stopped: {0}' -f $_.Exception.Message)
}
finally {
    try { $script:PendingAfter = @(Get-RebootSignals) }
    catch { Add-Problem -Text ('Final reboot check failed: {0}' -f $_.Exception.Message) }

    try { Write-FinalSummary }
    catch {
        $message = 'Could not finish writing the final summary: {0}' -f $_.Exception.Message
        $script:Problems.Add($message)
        Write-Host $message -ForegroundColor Red
    }

    Write-Host ''
    Write-Host 'Finished. This script did not request or schedule a restart.' -ForegroundColor Green

    if ($script:TranscriptStarted) {
        try { Stop-Transcript | Out-Null }
        catch { Write-Warning 'Transcript could not be closed cleanly.' }
    }
}

# Outside try/finally so the exit code cannot be swallowed; transcript is already closed.
exit (Get-ExitCode)
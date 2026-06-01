# Invoke-ScoutPerService.ps1
#
# Runs ScoutSuite against AWS one service at a time.
# Each service receives a separate report directory and log files.
#
# Run this script from the PowerShell session where HTTPS_PROXY is
# already configured correctly.

$ErrorActionPreference = 'Stop'

# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------

$ScoutExe = '.\Scripts\scout.exe'

# Restrict the scan to the authorised regions.
$Regions = @(
    'eu-west-2'
    'eu-central-1'
)

# These services were blocked by SCP restrictions in the previous run.
$ExcludedServices = @(
    'cloudfront'
    'directconnect'
)

# Stop an individual service scan after this many minutes and continue.
# Set to 0 to disable the timeout.
$PerServiceTimeoutMinutes = 45

# Stack traces can help diagnose services that fail.
$EnableDebug = $false

# Leave empty to discover all supported services automatically.
# To scan only selected services, add them here, for example:
#
# $ServicesOverride = @('iam', 's3', 'ec2')
#
$ServicesOverride = @()

# -------------------------------------------------------------------
# Collect AWS credentials without putting them in PowerShell history
# -------------------------------------------------------------------

function ConvertFrom-SecureStringPlainText {
    param(
        [Parameter(Mandatory)]
        [Security.SecureString] $SecureValue
    )

    $Ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureValue)

    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Ptr)
    }
    finally {
        if ($Ptr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Ptr)
        }
    }
}

$AccessKeyId = Read-Host 'AWS access key ID'

$SecretAccessKeySecure = Read-Host `
    'AWS secret access key' `
    -AsSecureString

$SessionTokenSecure = Read-Host `
    'AWS session token' `
    -AsSecureString

$SecretAccessKey = ConvertFrom-SecureStringPlainText $SecretAccessKeySecure
$SessionToken    = ConvertFrom-SecureStringPlainText $SessionTokenSecure

# -------------------------------------------------------------------
# Prepare output directory
# -------------------------------------------------------------------

$Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$RootDir   = Join-Path `
    (Get-Location) `
    "scoutsuite-per-service-$Timestamp"

New-Item `
    -ItemType Directory `
    -Path $RootDir `
    -Force |
    Out-Null

$SummaryFile = Join-Path $RootDir 'summary.csv'

Write-Host ''
Write-Host 'ScoutSuite per-service scan'
Write-Host "Output directory: $RootDir"
Write-Host ''

# -------------------------------------------------------------------
# Discover supported services
# -------------------------------------------------------------------

if ($ServicesOverride.Count -gt 0) {
    $Services = $ServicesOverride
}
else {
    Write-Host 'Discovering supported ScoutSuite services...'

    $ListOutput = (
        & $ScoutExe aws --list-services 2>&1 |
        Out-String
    )

    # Remove ANSI terminal colour sequences if present.
    $ListOutput = $ListOutput -replace "`e\[[\d;]*m", ''

    # ScoutSuite normally outputs quoted service names.
    $Services = [regex]::Matches(
        $ListOutput,
        '"([^"]+)"'
    ) |
        ForEach-Object {
            $_.Groups[1].Value.Trim()
        } |
        Where-Object {
            $_ -and $_ -notin $ExcludedServices
        } |
        Sort-Object -Unique

    if (-not $Services -or $Services.Count -eq 0) {
        Write-Host ''
        Write-Host 'Output returned by ScoutSuite:'
        Write-Host $ListOutput

        throw @'
Could not parse the list of services.

Run:
  .\Scripts\scout.exe aws --list-services

Then copy the required names into the $ServicesOverride array near the
top of this script.
'@
    }
}

Write-Host "Services to scan: $($Services.Count)"
Write-Host ($Services -join ', ')
Write-Host ''

Write-Host 'Excluded services:'
Write-Host ($ExcludedServices -join ', ')
Write-Host ''

# -------------------------------------------------------------------
# Scan one service at a time
# -------------------------------------------------------------------

$Results = [System.Collections.Generic.List[object]]::new()

foreach ($Service in $Services) {
    $ServiceDir = Join-Path $RootDir $Service

    New-Item `
        -ItemType Directory `
        -Path $ServiceDir `
        -Force |
        Out-Null

    $StdOutLog = Join-Path $ServiceDir 'stdout.log'
    $StdErrLog = Join-Path $ServiceDir 'stderr.log'
    $ReportName = "aws-$Service"

    $Arguments = @(
        'aws'
        '--access-keys'
        '--access-key-id'
        $AccessKeyId
        '--secret-access-key'
        $SecretAccessKey
        '--session-token'
        $SessionToken
        '--regions'
    )

    $Arguments += $Regions

    $Arguments += @(
        '--services'
        $Service
        '--report-dir'
        $ServiceDir
        '--report-name'
        $ReportName
        '--no-browser'
        '--force'
    )

    if ($EnableDebug) {
        $Arguments += '--debug'
    }

    $StartTime = Get-Date

    Write-Host ''
    Write-Host ('=' * 72)
    Write-Host "Starting service: $Service"
    Write-Host "Started:          $StartTime"
    Write-Host "Report folder:    $ServiceDir"
    Write-Host "Standard output:  $StdOutLog"
    Write-Host "Error output:     $StdErrLog"
    Write-Host ('=' * 72)

    $Process = Start-Process `
        -FilePath $ScoutExe `
        -ArgumentList $Arguments `
        -RedirectStandardOutput $StdOutLog `
        -RedirectStandardError $StdErrLog `
        -NoNewWindow `
        -PassThru

    $TimedOut = $false

    if ($PerServiceTimeoutMinutes -gt 0) {
        Wait-Process `
            -Id $Process.Id `
            -Timeout ($PerServiceTimeoutMinutes * 60) `
            -ErrorAction SilentlyContinue

        $Process.Refresh()

        if (-not $Process.HasExited) {
            $TimedOut = $true

            Write-Host ''
            Write-Host "Timeout reached for service: $Service"
            Write-Host "Stopping process ID: $($Process.Id)"

            Stop-Process `
                -Id $Process.Id `
                -Force `
                -ErrorAction SilentlyContinue
        }
    }
    else {
        Wait-Process -Id $Process.Id
    }

    $EndTime  = Get-Date
    $Duration = $EndTime - $StartTime

    $ExitCode = $null

    if (-not $TimedOut) {
        $Process.Refresh()
        $ExitCode = $Process.ExitCode
    }

    $Status = if ($TimedOut) {
        'TimedOut'
    }
    elseif ($ExitCode -eq 0) {
        'Completed'
    }
    else {
        'CompletedWithErrors'
    }

    $Results.Add(
        [PSCustomObject]@{
            Service         = $Service
            Status          = $Status
            ExitCode        = $ExitCode
            Started         = $StartTime
            Finished        = $EndTime
            DurationMinutes = [Math]::Round(
                $Duration.TotalMinutes,
                2
            )
            ReportDirectory = $ServiceDir
            StandardOutput  = $StdOutLog
            ErrorOutput     = $StdErrLog
        }
    )

    # Preserve partial progress after every service.
    $Results |
        Export-Csv `
            -Path $SummaryFile `
            -NoTypeInformation `
            -Force

    Write-Host ''
    Write-Host "Finished service: $Service"
    Write-Host "Status:           $Status"
    Write-Host "Duration:         $([Math]::Round($Duration.TotalMinutes, 2)) minutes"
}

# Remove plaintext credential variables when the scan finishes.
Remove-Variable SecretAccessKey -ErrorAction SilentlyContinue
Remove-Variable SessionToken    -ErrorAction SilentlyContinue

Write-Host ''
Write-Host ('=' * 72)
Write-Host 'All requested service scans have finished.'
Write-Host "Summary file: $SummaryFile"
Write-Host ('=' * 72)
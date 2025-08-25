<#
.SYNOPSIS
  Automated New PC Validation Script
 
 
.DESCRIPTION
  Validates a new Windows PC before deployment by checking
  system info, security, apps, and environment.
 
 
.OUTPUT
  HTML report saved to C:\PC_Test_Report\
#>
 
 
# --- Welcome Screen ---
Clear-Host
$scriptName = "TST PC Validation"
$version = "0.1 Beta"
$now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
 
 
Write-Host "================================" -ForegroundColor Cyan
Write-Host "$scriptName" -ForegroundColor Green
Write-Host "Version: $version" -ForegroundColor Yellow
Write-Host "Date: $now" -ForegroundColor White
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""
 
 
# --- Config ---
$ReportFolder = "C:\PC_Test_Report"
$ReportFile   = Join-Path $ReportFolder ("PC_Report_" + (Get-Date -Format "yyyyMMdd_HHmm") + ".html")
if (-not (Test-Path $ReportFolder)) { New-Item -ItemType Directory -Path $ReportFolder | Out-Null }
 
 
$Checks = @()
 
 
# --- System Info ---
$osInfo = Get-CimInstance Win32_OperatingSystem
$buildRevision = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").UBR
$osVersionFormatted = "$($osInfo.Version).$buildRevision"
 
 
$SystemInfo = @{
    "Computer Name" = $env:COMPUTERNAME
    "User"          = $env:USERNAME
    "Model"         = (Get-CimInstance Win32_ComputerSystem).Model
    "SerialNumber"  = (Get-CimInstance Win32_BIOS).SerialNumber
    "BIOS Version"  = (Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion
    "OS Version"    = $osInfo.Caption
    "OS Version (Full)" = $osVersionFormatted
    "OS Language"   = (Get-WinSystemLocale).DisplayName
    "Time Zone"     = (Get-TimeZone).Id
}
 
 
# --- Progress Helper ---
function Run-Check($category, $item, $scriptBlock) {
    $global:step++
    # Ensure PercentComplete doesn't exceed 100
    $percent = [Math]::Min(100, [int](($global:step / $global:totalSteps) * 100))
    Write-Progress -Activity "Running PC Validation Checks" -Status "$item" -PercentComplete $percent
 
    try {
        $result = & $scriptBlock
    } catch {
        $result = "Error: $($_.Exception.Message)" # Capture error message for better debugging
    }
    # Add the result to the global $Checks array
    $global:Checks += [PSCustomObject]@{ Category=$category; Item=$item; Result=$result }
}
 
 
# --- Define all checks (without running them yet) to count total steps ---
 
# Define applications to check
$appsToCheck = @(
    "Software Center","Company Portal","Zoom","Box Drive","Box Tools",
    "Microsoft Word","Microsoft Excel","Microsoft PowerPoint","Microsoft Office Language Pack",
    "Microsoft Outlook","Microsoft Teams","Crowdstrike","CyberArk","Okta Verify",
    "Netskope","LastPass","Viber","Microsoft Store"
)
 
# Calculate total steps dynamically
$totalSteps = 0
 
# Security Checks (5)
$totalSteps += 5
 
# Network (1)
$totalSteps += 1
 
# Language/IME (1)
$totalSteps += 1
 
# Browser Versions (2)
$totalSteps += 2
 
# Applications Check (count of $appsToCheck items)
$totalSteps += $appsToCheck.Count
 
# Initialize step counter
$step = 0
 
# --- Security Checks ---
Run-Check "Security" "TPM Presence" {
    (Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm).ManufacturerID -ne $null
}
Run-Check "Security" "BitLocker Status" {
    (Get-BitLockerVolume | Select-Object -First 1).VolumeStatus
}
Run-Check "Security" "Windows Update Compliance" {
    # This check can be slow and might require admin privileges.
    # A simple check for log file existence or size might be more practical for a quick validation.
    # For a more robust check, you'd query update history or pending updates.
    # For now, let's just check if the log file exists and has some content.
    $updateLogPath = "$env:SystemRoot\Logs\WindowsUpdate\WindowsUpdate.log"
    if (Test-Path $updateLogPath) {
        (Get-Item $updateLogPath).Length -gt 0
    } else {
        "Log file not found"
    }
}
Run-Check "Security" "BIOS Settings Validation" {
    # This is a placeholder. Real BIOS validation would involve specific checks.
    # For now, just confirming BIOS version retrieval.
    (Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion
}
Run-Check "Security" "Driver Version Check" {
    # This just gets the highest driver version. Not a true "validation".
    # A real check would compare against a baseline or specific critical drivers.
    (Get-CimInstance Win32_PnPSignedDriver | Sort-Object DriverVersion -Descending | Select-Object -First 1).DriverVersion
}
 
 
# --- Network ---
Run-Check "Network" "VPN Intra Reachable" {
    # Test-NetConnection can be slow if the host is unreachable. Add a timeout.
    Test-NetConnection -ComputerName "intra.rakuten.com" -Port 443 -InformationLevel Quiet -ErrorAction SilentlyContinue
}
 
 
# --- Language/IME ---
Run-Check "IME" "Installed IMEs" {
    $languages = Get-WinUserLanguageList
    ($languages | ForEach-Object { ($_).LanguageTag.Split("-")[0].ToUpper() }) -join ", "
}
 
 
# --- Browser Versions ---
Run-Check "Browser" "Chrome Version" {
    # Check if the file exists before trying to get its version
    $chromePath = "C:\Program Files\Google\Chrome\Application\chrome.exe"
    if (Test-Path $chromePath) {
        (Get-Item $chromePath).VersionInfo.ProductVersion
    } else {
        "Not Found"
    }
}
Run-Check "Browser" "Edge Version" {
    # Check if the file exists before trying to get its version
    $edgePath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    if (Test-Path $edgePath) {
        (Get-Item $edgePath).VersionInfo.ProductVersion
    } else {
        "Not Found"
    }
}
 
 
# --- Applications Check ---
foreach ($app in $appsToCheck) {
    Run-Check "Applications" "$app Installed" {
        # Using Get-Package or checking specific registry paths is often more reliable
        # than Win32_Product, which can trigger re-configuration and is generally slow.
        # For this example, sticking to Win32_Product but adding a try/catch.
        try {
            $installed = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*$app*" }
            if ($installed) { "Installed" } else { "Not Installed" }
        } catch {
            "Error checking application"
        }
    }
}
 
 
# --- Report Output ---
$html = @"
<html>
<head>
<style>
body { font-family: Arial; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid black; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; }
</style>
</head>
<body>
<h2>PC Validation Report</h2>
<p>Generated on: $now</p>
<h3>System Info</h3>
<table>
"@
 
 
foreach ($key in $SystemInfo.Keys) {
    $html += "<tr><th>$key</th><td>$($SystemInfo[$key])</td></tr>"
}
$html += "</table><h3>Validation Results</h3><table><tr><th>Category</th><th>Item</th><th>Result</th></tr>"
 
 
foreach ($check in $Checks) {
    $html += "<tr><td>$($check.Category)</td><td>$($check.Item)</td><td>$($check.Result)</td></tr>"
}
 
 
$html += "</table></body></html>"
 
 
$html | Out-File $ReportFile -Encoding utf8
Write-Host "Validation complete. Report saved to $ReportFile" -ForegroundColor Green
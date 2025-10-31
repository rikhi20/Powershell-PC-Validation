# Rakuten TST Validator
# ------------------------------------------------
# This script checks key system health parameters for Rakuten internal PCs.
# Output is generated in HTML format for easy review.


# --- CONFIGURATION ---
$ReportFile = "$env:TEMP\Rakuten_PC_Health_Report.html"
$totalSteps = 22 # update if you add/remove checks

# --- STEP INITIALIZATION FIX ---
$global:step = 0
if (-not $totalSteps -or $totalSteps -lt 1) { $totalSteps = 1 }

# --- ELEVATION CHECK ---
function Test-IsAdmin {
    $current = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Test-IsAdmin)) {
    Write-Warning "⚠️  This script is not running elevated. Some checks may fail (cert store, device info, bitlocker). Run PowerShell as Administrator for full results."
}

# --- FUNCTION: Write HTML Header/Footer ---
function Write-HtmlHeader {
    @"
<!DOCTYPE html>
<html>
<head>
<meta charset='UTF-8'>
<title>Rakuten PC Health Check Report</title>
<style>
body { font-family: 'Segoe UI', Arial, sans-serif; background-color: #f5f5f5; color: #333; }
h1 { color: #BF0000; }
table { width: 100%; border-collapse: collapse; margin-top: 20px; }
th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
th { background-color: #BF0000; color: white; }
tr:nth-child(even) { background-color: #f2f2f2; }
.success { color: green; font-weight: bold; }
.warning { color: orange; font-weight: bold; }
.fail { color: red; font-weight: bold; }
.note { color: #555; font-style: italic; }
</style>
</head>
<body>
<h1>Rakuten PC Health Check Report</h1>
<p>Generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
<table>
<tr><th>Category</th><th>Check</th><th>Result</th></tr>
"@ | Out-File -Encoding utf8 -FilePath $ReportFile
}

function Write-HtmlFooter {
    "</table></body></html>" | Out-File -Encoding utf8 -Append -FilePath $ReportFile
}

function Write-Result {
    param($Category, $Check, $Result)
    $escapedResult = [System.Web.HttpUtility]::HtmlEncode($Result)
    $cssClass = if ($Result -match '(^OK|Pass|Enabled|Present|Installed|Success|Activated)' -and $Result -notmatch 'Not|Fail|Missing|Error|Expired') {
        'success'
    } elseif ($Result -match 'Warn|Soon|Partial|Limited') {
        'warning'
    } elseif ($Result -match 'Fail|Missing|Not|Error|Expired') {
        'fail'
    } else {
        'note'
    }
    "<tr><td>$Category</td><td>$Check</td><td class='$cssClass'>$escapedResult</td></tr>" | Out-File -Encoding utf8 -Append -FilePath $ReportFile
}

# --- FUNCTION: Progress Wrapper ---
function Run-Check {
    param($Category, $CheckName, [ScriptBlock]$Check)
    $global:step++
    $progressPercent = [math]::Round(($global:step / $totalSteps) * 100)
    Write-Progress -Activity "Running Rakuten PC Health Checks" -Status "$CheckName ($progressPercent% complete)" -PercentComplete $progressPercent
    try {
        $result = & $Check
    } catch {
        $result = "Error: $($_.Exception.Message)"
    }
    Write-Result $Category $CheckName $result
}

# --- FUNCTION: Application Check (Improved Wildcard Handling) ---
function Test-ApplicationInstalled {
    param($DisplayNames, $ExecutablePaths)
    foreach ($name in $DisplayNames) {
        $regPaths = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        foreach ($reg in $regPaths) {
            $app = Get-ItemProperty -Path $reg -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*$name*" }
            if ($app) { return "Installed (v$($app.DisplayVersion))" }
        }
    }

    foreach ($exePath in $ExecutablePaths) {
        $expandedExePath = [Environment]::ExpandEnvironmentVariables($exePath)
        if ($expandedExePath -like "*`*") {
            $baseDir = Split-Path $expandedExePath -Parent
            if ([string]::IsNullOrEmpty($baseDir) -or -not (Test-Path $baseDir)) {
                $baseDir = $env:ProgramFiles
            }
            $fileNamePattern = Split-Path $expandedExePath -Leaf
            $foundFiles = Get-ChildItem -Path $baseDir -Filter $fileNamePattern -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($foundFiles) { $expandedExePath = $foundFiles.FullName } else { continue }
        }

        if (Test-Path $expandedExePath -PathType Leaf) {
            try {
                $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($expandedExePath)
                if ($versionInfo.ProductVersion) { return "Installed (v$($versionInfo.ProductVersion))" } else { return "Installed" }
            } catch { return "Installed (Path: $expandedExePath)" }
        }
    }
    return "Not Installed"
}

# --- BEGIN HTML ---
Write-HtmlHeader

# --- Checks ---

Run-Check "System" "Computer Name" { $env:COMPUTERNAME }

Run-Check "System" "Windows Version" {
    $os = Get-CimInstance Win32_OperatingSystem
    "$($os.Caption) (Build $($os.BuildNumber))"
}

Run-Check "System" "Uptime" {
    $os = Get-CimInstance Win32_OperatingSystem
    $uptime = (Get-Date) - $os.LastBootUpTime
    "$([math]::Round($uptime.TotalHours,1)) hours"
}

Run-Check "Network" "Intra Reachable" {
    try {
        if (Test-Connection -ComputerName "intra.rakuten.co.jp" -Count 1 -Quiet -ErrorAction SilentlyContinue) {
            "Ping Successful"
        } else {
            "Failed (Host Unreachable or DNS Resolution Failed)"
        }
    } catch { "Error: $($_.Exception.Message)" }
}

Run-Check "Network" "Proxy Settings" {
    $proxy = netsh winhttp show proxy | Out-String
    if ($proxy -match "Direct access") { "No Proxy Configured" } else { ($proxy -replace "`r`n", " ") }
}

Run-Check "System" "Disk Free Space (C:)" {
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
    $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
    $totalGB = [math]::Round($disk.Size / 1GB, 2)
    "$freeGB GB free of $totalGB GB"
}

Run-Check "Security" "BitLocker Status" {
    try {
        $bit = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop
        if ($bit.ProtectionStatus -eq 'On') { "Enabled" } else { "Disabled" }
    } catch { "BitLocker Module Unavailable or Not Supported" }
}

Run-Check "Security" "Windows Defender Status" {
    try {
        $status = Get-MpComputerStatus
        if ($status.AntivirusEnabled) { "Enabled (Definition v$($status.AntispywareSignatureVersion))" } else { "Disabled" }
    } catch { "Unable to Query Defender Status" }
}

Run-Check "Security" "Firewall Status" {
    $profiles = Get-NetFirewallProfile
    if ($profiles.Enabled -contains $false) { "Partially Disabled" } else { "Enabled" }
}

# --- Improved Corporate Cert Check ---
Run-Check "Security" "Corporate IT Root CA Certificate" {
    $output = @()
    $certFoundCount = 0
    $requiredCNs = @("Rakuten Corporate IT Root CA")
    try {
        $certs = @()
        $certs += Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue
        $certs += Get-ChildItem Cert:\LocalMachine\CA -ErrorAction SilentlyContinue
        $certs += Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue

        foreach ($req in $requiredCNs) {
            $foundCert = $certs | Where-Object { $_.Subject -like "*CN=$req*" -or $_.Subject -like "*$req*" } | Select-Object -First 1
            if ($foundCert) {
                $certFoundCount++
                $expiryDate = $foundCert.NotAfter.ToString("yyyy-MM-dd")
                $status = if ($foundCert.NotAfter -lt (Get-Date)) { "EXPIRED" } elseif ($foundCert.NotAfter -lt ((Get-Date).AddDays(30))) { "Expires Soon (<30 days)" } else { "Present" }
                $output += "[+] Found: $req (Expires: $expiryDate, Status: $status)"
            } else {
                $output += "[-] Missing: $req"
            }
        }

        if ($certFoundCount -eq $requiredCNs.Count) {
            "All Required Corporate Certificates Found:<br>$($output -join '<br>')"
        } elseif ($certFoundCount -gt 0) {
            "Some Corporate Certificates Missing or Expired:<br>$($output -join '<br>')"
        } else {
            "No Required Corporate Certificates Found.<br>$($output -join '<br>')"
        }
    } catch { "Error checking certificates: $($_.Exception.Message)" }
}

Run-Check "Applications" "Microsoft Teams" {
    Test-ApplicationInstalled @("Microsoft Teams", "Teams Machine-Wide Installer") @("$env:LOCALAPPDATA\Microsoft\Teams\current\Teams.exe", "$env:ProgramFiles(x86)\Microsoft\Teams\current\Teams.exe")
}

Run-Check "Applications" "Zoom" {
    Test-ApplicationInstalled @("Zoom") @("$env:APPDATA\Zoom\bin\Zoom.exe", "$env:ProgramFiles\Zoom\bin\Zoom.exe")
}

Run-Check "Applications" "Google Chrome" {
    Test-ApplicationInstalled @("Google Chrome") @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "$env:ProgramFiles(x86)\Google\Chrome\Application\chrome.exe")
}

Run-Check "Applications" "Slack" {
    Test-ApplicationInstalled @("Slack") @("$env:LOCALAPPDATA\slack\slack.exe")
}

Run-Check "Security" "Windows Update Service" {
    $service = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    if ($service.Status -eq 'Running') { "Running" } else { "Not Running" }
}

Run-Check "Hardware" "Battery Health" {
    try {
        $batt = Get-WmiObject Win32_Battery -ErrorAction Stop
        if ($batt) { "Battery Status: $($batt.Status)" } else { "No Battery Detected" }
    } catch { "Unable to Query Battery" }
}

Run-Check "Hardware" "TPM Status" {
    try {
        $tpm = Get-WmiObject -Namespace "Root\CIMV2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction Stop
        if ($tpm.IsEnabled_InitialValue) { "Enabled (v$($tpm.SpecVersion))" } else { "Disabled" }
    } catch { "TPM Not Available" }
}

Run-Check "System" "Antivirus Signature Age" {
    try {
        $status = Get-MpComputerStatus
        $sigDate = $status.AntivirusSignatureLastUpdated
        $daysOld = (New-TimeSpan -Start $sigDate -End (Get-Date)).Days
        if ($daysOld -le 3) { "Up-to-date ($daysOld days old)" } else { "Outdated ($daysOld days old)" }
    } catch { "Unable to Query Signature Age" }
}

Run-Check "Network" "Wi-Fi Signal Strength" {
    try {
        $wifi = netsh wlan show interfaces | Select-String "Signal"
        if ($wifi) { $wifi.ToString().Split(":")[1].Trim() } else { "Not Connected to Wi-Fi" }
    } catch { "Unable to Query Wi-Fi" }
}

Run-Check "System" "Last Boot Time" {
    (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
}

Run-Check "System" "Installed Memory" {
    "$([math]::Round((Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB,2)) GB"
}

Run-Check "System" "CPU Info" {
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    "$($cpu.Name) ($($cpu.NumberOfCores) Cores)"
}

# --- END REPORT ---
Write-HtmlFooter
Write-Host "`nReport generated at: $ReportFile" -ForegroundColor Green
Invoke-Item $ReportFile

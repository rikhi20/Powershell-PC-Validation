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
$version = "0.2 Beta" # Updated version
$now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

Write-Host "================================" -ForegroundColor Cyan
Write-Host "$scriptName" -ForegroundColor Green
Write-Host "Version: $version" -ForegroundColor Yellow
Write-Host "Date: $now" -ForegroundColor White
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This script will perform a series of validation checks on this PC." -ForegroundColor White
Write-Host "A detailed HTML report will be generated upon completion." -ForegroundColor White
Write-Host ""
Write-Host "Press any key to start the validation..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") # Waits for any key press

# --- Config ---
$ReportFolder = "C:\PC_Test_Report"
$ReportFile   = Join-Path $ReportFolder ("PC_Report_" + (Get-Date -Format "yyyyMMdd_HHmm") + ".html")

if (-not (Test-Path $ReportFolder)) { New-Item -ItemType Directory -Path $ReportFolder | Out-Null }

$Checks = @()

# --- System Info ---
$osInfo = Get-CimInstance Win32_OperatingSystem
$buildRevision = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").UBR
$osVersionFormatted = "$($osInfo.Version).$buildRevision"

# Determine AAD Join, Domain Join, and MECM Status
$aadJoined = (dsregcmd /status | Select-String "AzureAdJoined\s+:\s+YES" -Quiet)
$domainName = (Get-ComputerInfo -Property "CsDomain").CsDomain
$isDomainJoined = ($domainName -ne $env:COMPUTERNAME -and $domainName -ne $null -and $domainName -ne "")
$isMECMManaged = (Get-Service -Name "CcmExec" -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq "Running"}) -ne $null

$joinStatus = "Workgroup"
if ($isDomainJoined) {
    $joinStatus = "Domain Joined ($domainName)"
    if ($aadJoined) {
        $joinStatus = "Hybrid AAD Joined ($domainName)"
    }
} elseif ($aadJoined) {
    $joinStatus = "AAD Joined"
}

if ($isMECMManaged) {
    $joinStatus += " / MECM Managed"
} else {
    $joinStatus += " / Not MECM Managed"
}


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
    "Processor"     = (Get-CimInstance Win32_Processor).Name
    "Total Physical Memory" = "{0:N2} GB" -f ((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
    "Device Join Status" = $joinStatus
}

# --- Progress Helper ---
function Run-Check($category, $item, $scriptBlock) {
    $global:step++
    $percent = [Math]::Min(100, [int](($global:step / $global:totalSteps) * 100))
    Write-Progress -Activity "Running PC Validation Checks" -Status "$item" -PercentComplete $percent

    $result = "Error" # Default to error
    try {
        $result = & $scriptBlock
    } catch {
        $result = "Error: $($_.Exception.Message)" # Capture error message for better debugging
    }

    # Add the result to the global $Checks array
    $global:Checks += [PSCustomObject]@{ Category=$category; Item=$item; Result=$result }
}

# --- Application Check Helper Function ---
function Test-ApplicationInstalled {
    param (
        [string]$AppName,
        [string[]]$SearchStrings, # Strings to look for in DisplayName
        [string[]]$ExecutablePaths # Paths to check for existence
    )

    # 1. Check common Uninstall Registry Paths
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($path in $uninstallPaths) {
        if (Test-Path $path) {
            foreach ($entry in (Get-ItemProperty -Path "$path\*") | Where-Object { $_.DisplayName -ne $null }) {
                foreach ($searchString in $SearchStrings) {
                    if ($entry.DisplayName -like "*$searchString*") {
                        return "Installed (v$($entry.DisplayVersion))" # Return version if found
                    }
                }
            }
        }
    }

    # 2. Check specific executable paths
    foreach ($exePath in $ExecutablePaths) {
        if (Test-Path $exePath -PathType Leaf) {
            try {
                $versionInfo = (Get-Item $exePath).VersionInfo
                if ($versionInfo.ProductVersion) {
                    return "Installed (v$($versionInfo.ProductVersion))"
                } else {
                    return "Installed" # Found but no version info
                }
            } catch {
                return "Installed" # Found but couldn't get version (e.g., permission issue)
            }
        }
    }
    return "Not Installed"
}

# --- Define all checks and calculate total steps dynamically ---
# Define applications to check with their search strings and executable paths
$appsToCheck = @(
    @{ Name = "Software Center"; Search = @("Software Center", "SCCM Client"); Exec = @("c:\Windows\CCM\ClientUX\SCClient.exe") },
    @{ Name = "Company Portal"; Search = @("Company Portal", "Microsoft Intune Company Portal"); Exec = @("$env:ProgramFiles\WindowsApps\Microsoft.CompanyPortal_*\CompanyPortal.exe") }, # Store app, path can vary
    @{ Name = "Zoom"; Search = @("Zoom Meeting", "Zoom"); Exec = @("$env:AppData\Zoom\bin\Zoom.exe", "$env:ProgramFiles\Zoom\bin\Zoom.exe") },
    @{ Name = "Box Drive"; Search = @("Box Drive"); Exec = @("C:\Program Files\Box\Box\Box.exe") }, # Corrected path
    @{ Name = "Microsoft Word"; Search = @("Microsoft Office", "Microsoft 365", "Word"); Exec = @("$env:ProgramFiles\Microsoft Office\root\Office16\WINWORD.EXE", "$env:ProgramFiles(x86)\Microsoft Office\root\Office16\WINWORD.EXE") },
    @{ Name = "Microsoft Excel"; Search = @("Microsoft Office", "Microsoft 365", "Excel"); Exec = @("$env:ProgramFiles\Microsoft Office\root\Office16\EXCEL.EXE", "$env:ProgramFiles(x86)\Microsoft Office\root\Office16\EXCEL.EXE") },
    @{ Name = "Microsoft PowerPoint"; Search = @("Microsoft Office", "Microsoft 365", "PowerPoint"); Exec = @("$env:ProgramFiles\Microsoft Office\root\Office16\POWERPNT.EXE", "$env:ProgramFiles(x86)\Microsoft Office\root\Office16\POWERPNT.EXE") },
    @{ Name = "Microsoft Office Language Pack"; Search = @("Language Pack"); Exec = @("C:\Program Files\Microsoft Office\root\Office16\SETLANG.EXE") }, # Corrected path
    @{ Name = "Microsoft Outlook"; Search = @("Microsoft Office", "Microsoft 365", "Outlook"); Exec = @("$env:ProgramFiles\Microsoft Office\root\Office16\OUTLOOK.EXE", "$env:ProgramFiles(x86)\Microsoft Office\root\Office16\OUTLOOK.EXE") },
    @{ Name = "Microsoft Teams"; Search = @("Microsoft Teams"); Exec = @("$env:LocalAppData\Microsoft\Teams\current\Teams.exe", "$env:ProgramFiles\WindowsApps\MicrosoftTeams_*\Teams.exe") },
    @{ Name = "Crowdstrike Falcon"; Search = @("Crowdstrike Falcon Sensor"); Exec = @("$env:ProgramFiles\CrowdStrike\CSFalconService.exe") },
    @{ Name = "CyberArk"; Search = @("CyberArk EPM", "CyberArk Endpoint Privilege Manager"); Exec = @() }, # Check specific service or files if known
    @{ Name = "Okta Verify"; Search = @("Okta Verify"); Exec = @("$env:ProgramFiles\Okta\Okta Verify\Okta Verify.exe") },
    @{ Name = "Netskope Client"; Search = @("Netskope Client"); Exec = @("$env:ProgramFiles\Netskope\STAgent\STAgent.exe") },
    @{ Name = "LastPass"; Search = @("LastPass"); Exec = @() }, # Browser extension, harder to check via registry/exe. May need browser-specific check.
    @{ Name = "Viber"; Search = @("Viber"); Exec = @("$env:LocalAppData\Viber\Viber.exe") },
    @{ Name = "Microsoft Store"; Search = @("Microsoft Store"); Exec = @("$env:ProgramFiles\WindowsApps\Microsoft.WindowsStore_*\WinStore.App.exe") },
    @{ Name = "Zscaler Client Connector"; Search = @("Zscaler Client Connector", "Zscaler"); Exec = @("C:\Program Files\Zscaler\ZSATray\ZSATray.exe") } # Added Zscaler check
)

# Calculate total steps dynamically
$totalSteps = 0
$totalSteps += 5 # Security Checks
$totalSteps += 1 # Network
$totalSteps += 1 # Language/IME
$totalSteps += 2 # Browser Versions
$totalSteps += $appsToCheck.Count # Applications Check
$totalSteps += 3 # Windows Hello Checks (PIN Activated, Fingerprint Present, IR Camera Present)

$step = 0

# --- Actual Checks Start Here ---
# --- Security Checks ---
Run-Check "Security" "TPM Presence" {
    (Get-CimInstance -Namespace "Root\CIMv2\Security\MicrosoftTpm" -ClassName Win32_Tpm).ManufacturerID -ne $null
}

Run-Check "Security" "BitLocker Status" {
    # Check if any volume is encrypted
    $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
    if ($bitlockerVolumes) {
        $encryptedVolumes = $bitlockerVolumes | Where-Object {$_.VolumeStatus -eq "FullyEncrypted"}
        if ($encryptedVolumes.Count -gt 0) {
            "Enabled (Fully Encrypted)"
        } else {
            "Detected (Not Fully Encrypted)"
        }
    } else {
        "Not Detected"
    }
}

Run-Check "Security" "Windows Update Service Status" { # Renamed check item
    try {
        $service = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        if ($service) {
            if ($service.Status -eq "Running") {
                "Service Running"
            } else {
                "Service $($service.Status)"
            }
        } else {
            "Service Not Found"
        }
    } catch {
        "Error: $($_.Exception.Message)"
    }
}

Run-Check "Security" "BIOS Settings Validation" {
    # This just confirms BIOS version retrieval.
    (Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion
}

Run-Check "Security" "Driver Version Check" {
    # This just gets the highest driver version.
    (Get-CimInstance Win32_PnPSignedDriver | Sort-Object DriverVersion -Descending | Select-Object -First 1).DriverVersion
}

# --- Network ---
Run-Check "Network" "Intra Reachable" {
    # Ping only 'intra.rakuten.co.jp'
    $testResult = Test-Connection -ComputerName "intra.rakuten.co.jp" -Count 1 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    if ($testResult -and $testResult.StatusCode -eq 0) { # StatusCode 0 means success
        "Ping Successful"
    } else {
        "Failed (Host Unreachable)"
    }
}

# --- Language/IME ---
Run-Check "IME" "Installed IMEs" {
    $languages = Get-WinUserLanguageList
    ($languages | ForEach-Object { ($_).LanguageTag.Split("-")[0].ToUpper() }) -join ", "
}

# --- Browser Versions ---
Run-Check "Browser" "Chrome Version" {
    $chromePath = "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"
    if (Test-Path $chromePath -PathType Leaf) {
        (Get-Item $chromePath).VersionInfo.ProductVersion
    } else {
        "$chromePath Not Found"
    }
}

Run-Check "Browser" "Edge Version" {
    $edgeExePath = $null

    # --- Attempt 1: Check App Paths Registry ---
    try {
        $appPath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe" -ErrorAction SilentlyContinue)."(Default)"
        if ($appPath -and (Test-Path $appPath -PathType Leaf)) {
            $edgeExePath = $appPath
        }
    } catch {
        # Ignore error, proceed to next method
    }

    # --- Attempt 2: Fallback to Get-ChildItem -Recurse (if App Paths failed) ---
    if (-not $edgeExePath) {
        $edgeBasePaths = @(
            "$env:ProgramFiles\Microsoft\Edge\Application",
            "$env:ProgramFiles(x86)\Microsoft\Edge\Application"
        )
        foreach ($basePath in $edgeBasePaths) {
            if (Test-Path $basePath) {
                # Recursively search for msedge.exe within the application folder
                $foundExe = Get-ChildItem -Path $basePath -Recurse -File -Filter "msedge.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($foundExe) {
                    $edgeExePath = $foundExe.FullName
                    break
                }
            }
        }
    }

    if ($edgeExePath -and (Test-Path $edgeExePath -PathType Leaf)) {
        (Get-Item $edgeExePath).VersionInfo.ProductVersion
    } else {
        "msedge.exe Not Found in common paths"
    }
}

# --- Windows Hello Checks ---
Run-Check "Windows Hello" "Windows Hello PIN Activated" {
    # Checks if a Windows Hello PIN is setup and enabled for the current user.
    # A value of 1 for IsEnabled means a PIN is set up.
    try {
        $regPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\NgcPin"
        # Check if the registry path exists for the current user
        if (Test-Path $regPath) {
            $isEnabled = (Get-ItemProperty -Path $regPath -Name "IsEnabled" -ErrorAction SilentlyContinue).IsEnabled
            if ($isEnabled -eq 1) {
                "Activated"
            } else {
                "Not Activated"
            }
        } else {
            "Not Activated (Registry key not found for current user)"
        }
    } catch {
        "Not Activated (Error accessing registry: $($_.Exception.Message))"
    }
}

Run-Check "Windows Hello" "Fingerprint Module Present" {
    # Checks for the presence of a fingerprint reader device.
    $fingerprintSensor = Get-PnpDevice -Class Biometric -ErrorAction SilentlyContinue |
                         Where-Object {
                             ($_.FriendlyName -like "*fingerprint*" -or
                              $_.FriendlyName -like "*biometric sensor*" -or
                              $_.FriendlyName -like "*touch ID*" -or
                              $_.FriendlyName -like "*Goodix*" -or # Added Goodix
                              $_.FriendlyName -like "*Synaptics*") -and # Added Synaptics
                             $_.Status -eq "OK" # Check if the device is enabled and working
                         } | Select-Object -First 1

    if ($fingerprintSensor) {
        "Present (Device: $($fingerprintSensor.FriendlyName))"
    } else {
        "Not Present"
    }
}

Run-Check "Windows Hello" "Facial Recognition Capable IR Camera Present" {
    # Checks for the presence of an Infrared (IR) camera, commonly used for Windows Hello Face.
    $irCamera = Get-PnpDevice -ErrorAction SilentlyContinue |
                Where-Object {
                    ($_.FriendlyName -like "*IR Camera*" -or
                     $_.FriendlyName -like "*Infrared Camera*" -or
                     $_.FriendlyName -like "*Windows Hello Face*") -and
                    $_.Status -eq "OK" # Check if the device is enabled and working
                } | Select-Object -First 1

    if ($irCamera) {
        "Present (Device: $($irCamera.FriendlyName))"
    } else {
        "Not Present"
    }
}

# --- Applications Check ---
foreach ($app in $appsToCheck) {
    Run-Check "Applications" "$($app.Name) Status" {
        Test-ApplicationInstalled -AppName $app.Name -SearchStrings $app.Search -ExecutablePaths $app.Exec
    }
}

# --- Report Output ---
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PC Validation Report - $($SystemInfo."Computer Name")</title>
<style>
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        margin: 20px;
        background-color: #f4f7f6; /* Light gray background */
        color: #333;
    }
    .container {
        max-width: 1000px;
        margin: 0 auto;
        background-color: #ffffff;
        padding: 30px;
        border-radius: 8px;
        box-shadow: 0 4px 8px rgba(0,0,0,0.1);
    }
    h1, h2, h3 {
        color: #0056b3; /* Darker blue for headers */
        border-bottom: 2px solid #e0e0e0;
        padding-bottom: 5px;
        margin-top: 25px;
    }
    h1 {
        text-align: center;
        color: #004085;
        font-size: 2.2em;
        margin-bottom: 20px;
    }
    p {
        line-height: 1.6;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 15px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }
    th, td {
        border: 1px solid #ddd;
        padding: 12px 15px;
        text-align: left;
    }
    th {
        background-color: #e9ecef; /* Light gray for table headers */
        color: #495057;
        font-weight: bold;
        text-transform: uppercase;
    }
    tr:nth-child(even) {
        background-color: #f8f9fa; /* Lighter gray for even rows */
    }
    tr:hover {
        background-color: #e2f0fb; /* Light blue on hover */
    }
    /* Status Specific Colors */
    .status-positive { /* Green for positive results */
        color: #28a745;
        font-weight: bold;
    }
    .status-negative { /* Red for negative results */
        color: #dc3545;
        font-weight: bold;
    }
    .status-warning { /* Yellow/Orange for warnings */
        color: #ffc107;
        font-weight: bold;
    }
    .status-error { /* Gray for errors */
        color: #6c757d;
        font-weight: bold;
    }
    .status-info { /* Cyan/Info blue for general info (like versions) */
        color: #17a2b8;
    }
</style>
</head>
<body>
<div class="container">
    <h1>PC Validation Report</h1>
    <p><strong>Generated on:</strong> $now</p>
    <p><strong>Script Version:</strong> $version</p>
    <h2>System Information</h2>
    <table>
        <tbody>
"@

foreach ($key in $SystemInfo.Keys) {
    $html += "<tr><th>$key</th><td>$($SystemInfo[$key])</td></tr>"
}

$html += @"
        </tbody>
    </table>
    <h2>Validation Results</h2>
    <table>
        <thead>
            <tr>
                <th>Category</th>
                <th>Item</th>
                <th>Result</th>
            </tr>
        </thead>
        <tbody>
"@

foreach ($check in $Checks) {
    $resultClass = "status-info" # Default to info color
    $resultText = $check.Result

    # Prioritized logic for determining text color
    # 1. Negative results (Red) - Check these first and specifically
    if ($resultText -eq "False" -or
        $resultText -eq "Not Installed" -or # Exact match
        $resultText -eq "Not Detected" -or # Exact match
        $resultText -eq "Not Activated" -or # Exact match
        $resultText -eq "Not Present" -or # Exact match
        $resultText -like "*Failed*" -or
        $resultText -like "Service Stopped*" -or # Added for Windows Update Service
        $resultText -like "Service Disabled*" -or # Added for Windows Update Service
        $resultText -like "Service Not Found*") { # Added for Windows Update Service
        $resultClass = "status-negative"
    }
    # 2. Error results (Grey)
    elseif ($resultText -like "Error:*") { # Only match if it starts with "Error:"
        $resultClass = "status-error"
    }
    # 3. Warning results (Yellow/Orange)
    elseif ($resultText -like "*Detected (Not Fully Encrypted)*" -or # Specific warning for BitLocker
            $resultText -like "*Warning*" -or
            $resultText -like "*Partial*") {
        $resultClass = "status-warning"
    }
    # 4. Positive results (Green) - Check these after all negative/error/warning
    elseif ($resultText -eq "True" -or # Exact match
            $resultText -like "*Installed (v*" -or # Specific for app versions
            $resultText -eq "Installed" -or # Exact match
            $resultText -like "*Success*" -or
            $resultText -like "*Enabled*" -or
            $resultText -like "*Activated*" -or
            $resultText -like "*Present (Device:*" -or # Specific for "Present (Device: ...)"
            $resultText -eq "Present" -or # Exact match for "Present"
            $resultText -like "*Ping Successful*" -or
            $resultText -like "Service Running*") { # Added for Windows Update Service
        $resultClass = "status-positive"
    }
    # 5. All other results (Info/Cyan - default)
    # No 'else' needed here, as $resultClass defaults to 'status-info'

    $html += "<tr>"
    $html += "<td>$($check.Category)</td>"
    $html += "<td>$($check.Item)</td>"
    $html += "<td class='$resultClass'>$($check.Result)</td>"
    $html += "</tr>"
}

$html += @"
        </tbody>
    </table>
</div>
</body>
</html>
"@

$html | Out-File $ReportFile -Encoding utf8
Write-Host "Validation complete. Report saved to $ReportFile" -ForegroundColor Green
Invoke-Item $ReportFile # Open the report automatically

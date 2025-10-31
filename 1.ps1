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
$version = "0.7 Beta" # Updated version for focused cert check
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

# Get Main Display Resolution
$displayResolution = ""
try {
    # Attempt to get resolution using WMI (often more accurate for primary active display)
    $display = Get-WmiObject -Namespace root\wmi -Class WmiMonitorResolution -ErrorAction SilentlyContinue | Where-Object {$_.Active -eq $true} | Select-Object -First 1
    if ($display) {
        $displayResolution = "$($display.HorizontalPixels)x$($display.VerticalPixels)"
    } else {
        # Fallback to System.Windows.Forms.Screen if WMI fails or doesn't find active display
        # This requires the .NET Framework assembly to be loaded
        Add-Type -AssemblyName System.Windows.Forms
        $screen = [System.Windows.Forms.Screen]::PrimaryScreen
        if ($screen) {
            $displayResolution = "$($screen.Bounds.Width)x$($screen.Bounds.Height) (Fallback)"
        } else {
            $displayResolution = "Not detected or no active display found."
        }
    }
} catch {
    $displayResolution = "Error getting display resolution: $($_.Exception.Message)"
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
    "Main Display Resolution" = $displayResolution # Added display resolution
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
$totalSteps += 6 # Security Checks (TPM, BitLocker, WU Service, BIOS, Driver, Corporate Certs)
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

Run-Check "Security" "Windows Update Service Status" {
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

Run-Check "Security" "Corporate IT Root CA Certificate" {
    $output = @()
    $certFoundCount = 0
    # Only this specific certificate is required
    $requiredCerts = @(
        "CN=Rakuten Corporate IT Root CA, DC=intra, DC=rakuten, DC=co, DC=jp"
    )

    try {
        # Root CAs are typically in the Root store
        $certsRoot = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue
        # Also check My store just in case, though less common for a Root CA
        $certsMy = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue
        # Intermediate CAs store is unlikely for a Root CA itself, but good to keep in mind
        $certsIntermediate = Get-ChildItem Cert:\LocalMachine\CA -ErrorAction SilentlyContinue

        # Combine all relevant collections into a single, flat array
        $certsToSearch = @($certsRoot) + @($certsMy) + @($certsIntermediate)

        foreach ($requiredCertCN in $requiredCerts) {
            # Extract a more readable name from the full subject string
            $displayCertName = $requiredCertCN
            if ($requiredCertCN.StartsWith("CN=")) {
                $displayCertName = ($requiredCertCN -split ',')[0] -replace 'CN=', ''
            } # For a root CA, it's usually a simple CN.

            $foundCert = $certsToSearch | Where-Object { $_.Subject -eq $requiredCertCN } | Select-Object -First 1

            if ($foundCert) {
                $certFoundCount++
                $status = "Present"
                $expiryDate = $foundCert.NotAfter.ToString("yyyy-MM-dd") # Format expiry date
                if ($foundCert.NotAfter -lt (Get-Date)) {
                    $status = "EXPIRED"
                } elseif ($foundCert.NotAfter -lt ((Get-Date).AddDays(30))) {
                    $status = "Expires Soon (<30 days)"
                }
                $output += "[+] Found: $($displayCertName) (Expires: $expiryDate, Status: $status)"
            } else {
                $output += "[-] Missing: $displayCertName"
            }
        }

        if ($certFoundCount -eq $requiredCerts.Count) {
            "All Required Corporate Certificates Found: $($output -join '<br>')"
        } elseif ($certFoundCount -gt 0) {
            "Some Corporate Certificates Missing or Expired:<br>$($output -join '<br>')"
        } else {
            "No Required Corporate Certificates Found.<br>$($output -join '<br>')"
        }
    } catch {
        "Error checking certificates: $($_.Exception.Message)"
    }
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
        $sid = $null
        # Try to get SID from AD for domain users
        $adUser = Get-ADUser -Identity $env:USERNAME -Properties SID -ErrorAction SilentlyContinue
        if ($adUser) {
            $sid = $adUser.SID.Value
        } else {
            # Fallback for local users or if Get-ADUser fails (e.g., not domain joined, AD module not present)
            $localUser = Get-CimInstance Win32_UserAccount | Where-Object {$_.Name -eq $env:USERNAME -and $_.LocalAccount -eq $true}
            if ($localUser) {
                $sid = $localUser.SID
            }
        }

        if ($sid) {
            # Path for Windows Hello for Business (key provisioning)
            $whfbRegPath = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\State"
            # Path for consumer Windows Hello (PIN provisioning)
            $pinRegPath = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\Storage\Pin"

            $isWhfbProvisioned = $false
            $isPinProvisioned = $false

            # Check for Windows Hello for Business provisioning
            if (Test-Path $whfbRegPath) {
                $stateValue = (Get-ItemProperty -LiteralPath $whfbRegPath -Name "State" -ErrorAction SilentlyContinue).State
                # State value 0x70000 indicates WHfB key provisioning completed
                if ($stateValue -eq 0x70000) {
                    $isWhfbProvisioned = $true
                }
            }

            # Check for consumer PIN provisioning
            if (Test-Path $pinRegPath) {
                # The presence of this key, specifically the "Pin" subkey,
                # usually indicates a PIN has been set up.
                $isPinProvisioned = $true
            }

            if ($isWhfbProvisioned -or $isPinProvisioned) {
                "Activated"
            } else {
                "Not Activated"
            }
        } else {
            "Not Activated (Could not determine user SID)"
        }
    } catch {
        "Not Activated (Error checking PIN status: $($_.Exception.Message))"
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
        background-color: #f8f8f8; /* Very light gray background for contrast */
        color: #333;
    }
    .container {
        max-width: 1000px;
        margin: 0 auto;
        background-color: #ffffff;
        padding: 30px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15); /* Stronger shadow */
    }
    h1, h2, h3 {
        color: #DC143C; /* Crimson Red for headers */
        border-bottom: 2px solid #e0e0e0;
        padding-bottom: 5px;
        margin-top: 25px;
    }
    h1 {
        text-align: center;
        color: #B22222; /* Firebrick for main title */
        font-size: 2.5em;
        margin-bottom: 25px;
    }
    p {
        line-height: 1.6;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 15px;
        box-shadow: 0 2px 6px rgba(0,0,0,0.08); /* Slightly stronger table shadow */
    }
    th, td {
        border: 1px solid #eee; /* Lighter border */
        padding: 12px 15px;
        text-align: left;
    }
    th {
        background-color: #F5F5F5; /* Very light gray for table headers */
        color: #555;
        font-weight: bold;
        text-transform: uppercase;
    }
    tr:nth-child(even) {
        background-color: #FDFDFD; /* Almost white for even rows */
    }
    tr:hover {
        background-color: #FFF0F5; /* Light pink on hover */
    }
    /* Status Specific Colors */
    .status-positive { /* Green for positive results */
        color: #28a745;
        font-weight: bold;
    }
    .status-negative { /* Red for negative results */
        color: #DC143C; /* Crimson Red for negative */
        font-weight: bold;
    }
    .status-warning { /* Orange for warnings */
        color: #ffc107;
        font-weight: bold;
    }
    .status-error { /* Gray for errors */
        color: #6c757d;
        font-weight: bold;
    }
    .status-info { /* Darker gray for general info (less emphasis) */
        color: #555;
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
        $resultText -like "Service Stopped*" -or
        $resultText -like "Service Disabled*" -or
        $resultText -like "Service Not Found*" -or
        $resultText -like "*EXPIRED*" -or # Added for certificate check
        $resultText -like "[-] Missing*" # Modified for certificate check
        ) {
        $resultClass = "status-negative"
    }
    # 2. Error results (Grey)
    elseif ($resultText -like "Error:*") { # Only match if it starts with "Error:"
        $resultClass = "status-error"
    }
    # 3. Warning results (Yellow/Orange)
    elseif ($resultText -like "*Detected (Not Fully Encrypted)*" -or # Specific warning for BitLocker
            $resultText -like "*Warning*" -or
            $resultText -like "*Partial*" -or
            $resultText -like "*Expires Soon*" -or # Added for certificate check
            $resultText -like "Some Corporate Certificates Missing*" # Added for certificate check summary
            ) {
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
            $resultText -like "Service Running*" -or
            $resultText -like "[+] Found:*" -or # Modified for certificate check
            $resultText -like "All Required Corporate Certificates Found*" # Added for certificate check summary
            ) {
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

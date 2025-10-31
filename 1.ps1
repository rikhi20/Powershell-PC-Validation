Okay, here is the full, corrected, and improved PowerShell script for automated PC validation. I've incorporated the fix for the `param` statement error and included all the enhancements discussed previously.

```powershell
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
$version = "0.8 Beta" # Updated version for focused cert check and other improvements
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
# Waits for any key press without echoing it to the console.
$null = $Host.UI.RawUI.ReadKey([System.Management.Automation.Host.ReadKeyOptions]::NoEcho -bor [System.Management.Automation.Host.ReadKeyOptions]::IncludeKeyDown)

# --- Config ---
$ReportFolder = "C:\PC_Test_Report"
$ReportFile   = Join-Path $ReportFolder ("PC_Report_" + (Get-Date -Format "yyyyMMdd_HHmm") + ".html")

if (-not (Test-Path $ReportFolder)) {
    try {
        New-Item -ItemType Directory -Path $ReportFolder | Out-Null
    } catch {
        Write-Error "Failed to create report folder '$ReportFolder': $($_.Exception.Message)"
        Exit 1 # Exit if report folder cannot be created
    }
}

$Checks = @() # Global array to store check results

# --- System Info Collection ---
$osInfo = Get-CimInstance Win32_OperatingSystem -Property Caption, Version, OSArchitecture -ErrorAction SilentlyContinue
$buildRevision = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue).UBR
$osVersionFormatted = if ($osInfo) { "$($osInfo.Version).$buildRevision" } else { "N/A" }

# Determine AAD Join, Domain Join, and MECM Status
$aadJoined = (dsregcmd /status 2>&1 | Select-String "AzureAdJoined\s+:\s+YES" -Quiet)
$domainName = (Get-ComputerInfo -Property "CsDomain" -ErrorAction SilentlyContinue).CsDomain
$isDomainJoined = ($domainName -ne $env:COMPUTERNAME -and -not [string]::IsNullOrEmpty($domainName) -and $domainName -ne "WORKGROUP")
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
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
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
    "Computer Name"         = $env:COMPUTERNAME
    "User"                  = $env:USERNAME
    "Model"                 = (Get-CimInstance Win32_ComputerSystem -Property Model -ErrorAction SilentlyContinue).Model
    "SerialNumber"          = (Get-CimInstance Win32_BIOS -Property SerialNumber -ErrorAction SilentlyContinue).SerialNumber
    "BIOS Version"          = (Get-CimInstance Win32_BIOS -Property SMBIOSBIOSVersion -ErrorAction SilentlyContinue).SMBIOSBIOSVersion
    "OS Version"            = if ($osInfo) { $osInfo.Caption } else { "N/A" }
    "OS Version (Full)"     = $osVersionFormatted
    "OS Architecture"       = if ($osInfo) { $osInfo.OSArchitecture } else { "N/A" }
    "OS Language"           = (Get-WinSystemLocale -ErrorAction SilentlyContinue).DisplayName
    "Time Zone"             = (Get-TimeZone).Id
    "Processor"             = (Get-CimInstance Win32_Processor -Property Name -ErrorAction SilentlyContinue).Name
    "Total Physical Memory" = "{0:N2} GB" -f ((Get-CimInstance Win32_ComputerSystem -Property TotalPhysicalMemory -ErrorAction SilentlyContinue).TotalPhysicalMemory / 1GB)
    "Device Join Status"    = $joinStatus
    "Main Display Resolution" = $displayResolution
}

# --- Progress Helper Function ---
function Run-Check {
    param (
        [string]$category,
        [string]$item,
        [scriptblock]$scriptBlock
    )
    $global:step++
    $percent = [Math]::Min(100, [int](($global:step / $global:totalSteps) * 100))
    Write-Progress -Activity "Running PC Validation Checks" -Status "$item" -PercentComplete $percent

    $result = "Error: Unhandled exception" # Default to error
    try {
        $checkResult = & $scriptBlock
        if ($checkResult -is [System.Collections.IEnumerable] -and $checkResult -isnot [string]) {
            # Join array results with <br> for HTML, escaping each item
            $result = ($checkResult | ForEach-Object { [System.Security.SecurityElement]::Escape($_) }) -join '<br>'
        } else {
            # Escape the string result for HTML output
            $result = [System.Security.SecurityElement]::Escape($checkResult.ToString())
        }
    } catch {
        # Capture and escape error message
        $result = "Error: $([System.Security.SecurityElement]::Escape($_.Exception.Message))"
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
            foreach ($entry in (Get-ItemProperty -Path "$path\*" -ErrorAction SilentlyContinue) | Where-Object { $_.DisplayName -ne $null }) {
                foreach ($searchString in $SearchStrings) {
                    if ($entry.DisplayName -like "*$searchString*") {
                        # Attempt to get version, if not available, just return "Installed"
                        $version = if ($entry.DisplayVersion) { "v$($entry.DisplayVersion)" } else { "" }
                        return "Installed $($version)".Trim()
                    }
                }
            }
        }
    }

    # 2. Check specific executable paths
    foreach ($exePath in $ExecutablePaths) {
        # Expand environment variables in the path
        $expandedExePath = [Environment]::ExpandEnvironmentVariables($exePath)

        # Handle wildcard paths for store apps (e.g., Microsoft.CompanyPortal_*)
        if ($expandedExePath -like "*\*") {
            # Extract base directory and filename pattern
            $baseDir = Split-Path $expandedExePath | Split-Path -Parent # Get parent directory for wildcard search
            $fileNamePattern = Split-Path $expandedExePath -Leaf

            $foundFiles = Get-ChildItem -Path $baseDir -Filter $fileNamePattern -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($foundFiles) {
                $expandedExePath = $foundFiles.FullName
            } else {
                continue # If wildcard path doesn't resolve, try next path
            }
        }

        if (Test-Path $expandedExePath -PathType Leaf) {
            try {
                $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($expandedExePath)
                if ($versionInfo.ProductVersion) {
                    return "Installed (v$($versionInfo.ProductVersion))"
                } else {
                    return "Installed" # Found but no version info
                }
            } catch {
                return "Installed (Path: $($expandedExePath))" # Found but couldn't get version (e.g., permission issue)
            }
        }
    }

    return "Not Installed"
}

# --- Define applications to check and calculate total steps dynamically ---
$appsToCheck = @(
    @{ Name = "Software Center"; Search = @("Software Center", "SCCM Client"); Exec = @("c:\Windows\CCM\ClientUX\SCClient.exe") },
    @{ Name = "Company Portal"; Search = @("Company Portal", "Microsoft Intune Company Portal"); Exec = @("$env:ProgramFiles\WindowsApps\Microsoft.CompanyPortal_*\CompanyPortal.exe") }, # Store app, path can vary
    @{ Name = "Zoom"; Search = @("Zoom Meeting", "Zoom"); Exec = @("$env:AppData\Zoom\bin\Zoom.exe", "$env:ProgramFiles\Zoom\bin\Zoom.exe") },
    @{ Name = "Box Drive"; Search = @("Box Drive"); Exec = @("C:\Program Files\Box\Box\Box.exe") },
    @{ Name = "Microsoft Word"; Search = @("Microsoft Office", "Microsoft 365", "Word"); Exec = @("$env:ProgramFiles\Microsoft Office\root\Office16\WINWORD.EXE", "$env:ProgramFiles(x86)\Microsoft Office\root\Office16\WINWORD.EXE") },
    @{ Name = "Microsoft Excel"; Search = @("Microsoft Office", "Microsoft 365", "Excel"); Exec = @("$env:ProgramFiles\Microsoft Office\root\Office16\EXCEL.EXE", "$env:ProgramFiles(x86)\Microsoft Office\root\Office16\EXCEL.EXE") },
    @{ Name = "Microsoft PowerPoint"; Search = @("Microsoft Office", "Microsoft 365", "PowerPoint"); Exec = @("$env:ProgramFiles\Microsoft Office\root\Office16\POWERPNT.EXE", "$env:ProgramFiles(x86)\Microsoft Office\root\Office16\POWERPNT.EXE") },
    @{ Name = "Microsoft Office Language Pack"; Search = @("Language Pack"); Exec = @("C:\Program Files\Microsoft Office\root\Office16\SETLANG.EXE") },
    @{ Name = "Microsoft Outlook"; Search = @("Microsoft Office", "Microsoft 365", "Outlook"); Exec = @("$env:ProgramFiles\Microsoft Office\root\Office16\OUTLOOK.EXE", "$env:ProgramFiles(x86)\Microsoft Office\root\Office16\OUTLOOK.EXE") },
    @{ Name = "Microsoft Teams (New)"; Search = @("Microsoft Teams (work or school)"); Exec = @("$env:LocalAppData\Microsoft\Teams\current\Teams.exe") }, # New Teams path
    @{ Name = "Microsoft Teams (Classic)"; Search = @("Microsoft Teams"); Exec = @("$env:ProgramFiles\WindowsApps\MicrosoftTeams_*\Teams.exe") }, # Classic Teams (Store app)
    @{ Name = "Crowdstrike Falcon"; Search = @("Crowdstrike Falcon Sensor"); Exec = @("$env:ProgramFiles\CrowdStrike\CSFalconService.exe") },
    @{ Name = "CyberArk EPM"; Search = @("CyberArk EPM", "CyberArk Endpoint Privilege Manager"); Exec = @() }, # Requires specific service/file check if registry fails
    @{ Name = "Okta Verify"; Search = @("Okta Verify"); Exec = @("$env:ProgramFiles\Okta\Okta Verify\Okta Verify.exe", "$env:LocalAppData\Programs\Okta\Okta Verify\Okta Verify.exe") },
    @{ Name = "Netskope Client"; Search = @("Netskope Client"); Exec = @("$env:ProgramFiles\Netskope\STAgent\STAgent.exe") },
    @{ Name = "LastPass Desktop"; Search = @("LastPass"); Exec = @() }, # Often a browser extension or minimal desktop app, registry check is primary
    @{ Name = "Viber"; Search = @("Viber"); Exec = @("$env:LocalAppData\Viber\Viber.exe", "$env:ProgramFiles\Viber\Viber.exe") },
    @{ Name = "Microsoft Store"; Search = @("Microsoft Store"); Exec = @("$env:ProgramFiles\WindowsApps\Microsoft.WindowsStore_*\WinStore.App.exe") },
    @{ Name = "Zscaler Client Connector"; Search = @("Zscaler Client Connector", "Zscaler"); Exec = @("C:\Program Files\Zscaler\ZSATray\ZSATray.exe") }
)

# Calculate total steps dynamically for progress bar
$totalSteps = 0
$totalSteps += 6 # Security Checks (TPM, BitLocker, WU Service, BIOS, Driver, Corporate Certs)
$totalSteps += 1 # Network
$totalSteps += 1 # Language/IME
$totalSteps += 2 # Browser Versions
$totalSteps += $appsToCheck.Count # Applications Check
$totalSteps += 3 # Windows Hello Checks (PIN Activated, Fingerprint Present, IR Camera Present)
$step = 0 # Initialize step counter for progress bar

# --- Actual Checks Start Here ---

# --- Security Checks ---
Run-Check "Security" "TPM Presence" {
    $tpm = Get-CimInstance -Namespace "Root\CIMv2\Security\MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction SilentlyContinue
    if ($tpm -and $tpm.ManufacturerID -ne $null) {
        "Present (Manufacturer ID: $($tpm.ManufacturerID))"
    } else {
        "Not Present or Not Detected"
    }
}

Run-Check "Security" "BitLocker Status" {
    try {
        $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
        if ($bitlockerVolumes) {
            $encryptedVolumes = $bitlockerVolumes | Where-Object {$_.VolumeStatus -eq "FullyEncrypted"}
            $partiallyEncrypted = $bitlockerVolumes | Where-Object {$_.VolumeStatus -eq "EncryptionInProgress"}
            if ($encryptedVolumes.Count -gt 0) {
                "Enabled (Fully Encrypted)"
            } elseif ($partiallyEncrypted.Count -gt 0) {
                "Detected (Encryption In Progress)"
            } else {
                "Detected (Not Fully Encrypted / Disabled)"
            }
        } else {
            "Not Detected (BitLocker cmdlets not available or no BitLocker volumes)"
        }
    } catch {
        "Error checking BitLocker: $($_.Exception.Message)"
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
    # This check primarily confirms BIOS version retrieval.
    # More advanced validation would involve checking specific BIOS settings via WMI or manufacturer tools.
    $biosVersion = (Get-CimInstance Win32_BIOS -Property SMBIOSBIOSVersion -ErrorAction SilentlyContinue).SMBIOSBIOSVersion
    if ([string]::IsNullOrEmpty($biosVersion)) {
        "BIOS Version Not Detected"
    } else {
        $biosVersion
    }
}

Run-Check "Security" "Driver Version Check" {
    # This check simply gets the version of the most recently signed driver.
    # A true "validation" would compare against a baseline or specific driver versions.
    $latestDriver = Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
                    Sort-Object DriverVersion -Descending |
                    Select-Object -First 1 -Property DriverVersion, DeviceName

    if ($latestDriver) {
        "Latest Driver: $($latestDriver.DeviceName) (v$($latestDriver.DriverVersion))"
    } else {
        "No signed drivers found or error retrieving."
    }
}

Run-Check "Security" "Corporate IT Root CA Certificate" {
    $output = @()
    $certFoundCount = 0

    # Only this specific certificate is required for Rakuten
    $requiredCerts = @(
        "CN=Rakuten Corporate IT Root CA, DC=intra, DC=rakuten, DC=co, DC=jp"
    )

    try {
        # Root CAs are typically in the Root store
        $certsRoot = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue
        # Also check My store and CA store just in case, though less common for a Root CA
        $certsMy = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue
        $certsIntermediate = Get-ChildItem Cert:\LocalMachine\CA -ErrorAction SilentlyContinue

        # Combine all relevant collections into a single, flat array
        $certsToSearch = @($certsRoot) + @($certsMy) + @($certsIntermediate)

        foreach ($requiredCertCN in $requiredCerts) {
            # Extract a more readable name from the full subject string
            $displayCertName = $requiredCertCN
            if ($requiredCertCN.StartsWith("CN=")) {
                $displayCertName = ($requiredCertCN -split ',')[0] -replace 'CN=', ''
            }

            $foundCert = $certsToSearch | Where-Object { $_.Subject -eq $requiredCertCN } | Select-Object -First 1

            if ($foundCert) {
                $certFoundCount++
                $status = "Present"
                $expiryDate = $foundCert.NotAfter.ToString("yyyy-MM-dd")

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
    try {
        $testResult = Test-Connection -ComputerName "intra.rakuten.co.jp" -Count 1 -ErrorAction SilentlyContinue
        if ($testResult -and $testResult.StatusCode -eq 0) { # StatusCode 0 means success
            "Ping Successful"
        } else {
            "Failed (Host Unreachable or DNS Resolution Failed)"
        }
    } catch {
        "Error: $($_.Exception.Message)"
    }
}

# --- Language/IME ---
Run-Check "IME" "Installed IMEs" {
    try {
        $languages = Get-WinUserLanguageList -ErrorAction SilentlyContinue
        if ($languages) {
            ($languages | ForEach-Object { ($_.LanguageTag.Split("-")[0].ToUpper()) }) -join ", "
        } else {
            "No user languages found."
        }
    } catch {
        "Error: $($_.Exception.Message)"
    }
}

# --- Browser Versions ---
Run-Check "Browser" "Chrome Version" {
    $chromePath = "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"
    if (Test-Path $chromePath -PathType Leaf) {
        try {
            [System.Diagnostics.FileVersionInfo]::GetVersionInfo($chromePath).ProductVersion
        } catch {
            "Found, but error getting version: $($_.Exception.Message)"
        }
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
        try {
            [System.Diagnostics.FileVersionInfo]::GetVersionInfo($edgeExePath).ProductVersion
        } catch {
            "Found, but error getting version: $($_.Exception.Message)"
        }
    } else {
        "msedge.exe Not Found in common paths"
    }
}

# --- Windows Hello Checks ---
Run-Check "Windows Hello" "Windows Hello PIN Activated" {
    try {
        # Get the Security Identifier (SID) for the current user
        $userSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
        # Define the registry path for the Windows Hello PIN credential provider
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{D6886603-9D2F-4EB2-B667-1971041FA96B}\$userSID"

        # Check if the registry key for the user's SID exists
        if (Test-Path $registryPath) {
            # If the key exists, check the 'LogonCredsAvailable' value
            $value = Get-ItemProperty -Path $registryPath -Name "LogonCredsAvailable" -ErrorAction SilentlyContinue
            if ($value -and $value.LogonCredsAvailable -eq 1) {
                "Activated (LogonCredsAvailable = 1)"
            } else {
                "Not Activated (LogonCredsAvailable value not 1 or not found)"
            }
        } else {
            "Not Activated (No Windows Hello for Business enrollment found in registry for current user.)"
        }
    } catch {
        "Error checking PIN status: $($_.Exception.Message)"
    }
}

Run-Check "Windows Hello" "Fingerprint Module Present" {
    try {
        # Checks for the presence of a fingerprint reader device.
        $fingerprintSensor = Get-PnpDevice -Class Biometric -ErrorAction SilentlyContinue |
            Where-Object {
                ($_.FriendlyName -like "*fingerprint*" -or
                $_.FriendlyName -like "*biometric sensor*" -or
                $_.FriendlyName -like "*touch ID*" -or
                $_.FriendlyName -like "*Goodix*" -or
                $_.FriendlyName -like "*Synaptics*") -and
                $_.Status -eq "OK" # Check if the device is enabled and working
            } | Select-Object -First 1
        if ($fingerprintSensor) {
            "Present (Device: $($fingerprintSensor.FriendlyName))"
        } else {
            "Not Present"
        }
    } catch {
        "Error checking fingerprint module: $($_.Exception.Message)"
    }
}

Run-Check "Windows Hello" "Facial Recognition Capable IR Camera Present" {
    try {
        # Checks for the presence of an Infrared (IR) camera, commonly used for Windows Hello Face.
        $irCamera = Get-PnpDevice -ErrorAction SilentlyContinue |
            Where-Object {
                ($_.FriendlyName -like "*IR Camera*" -or
                $_.FriendlyName -like "*Infrared Camera*" -or
                $_.FriendlyName -like "*Windows Hello Face*" -or
                $_.FriendlyName -like "*Hello Camera*") -and # Added for broader detection
                $_.Status -eq "OK" # Check if the device is enabled and working
            } | Select-Object -First 1
        if ($irCamera) {
            "Present (Device: $($irCamera.FriendlyName))"
        } else {
            "Not Present"
        }
    } catch {
        "Error checking IR camera: $($_.Exception.Message)"
    }
}

# --- Applications Check ---
foreach ($app in $appsToCheck) {
    Run-Check "Applications" "$($app.Name) Status" {
        Test-ApplicationInstalled -AppName $app.Name -SearchStrings $app.Search -ExecutablePaths $app.Exec
    }
}

# --- Report Output Generation ---
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
    # Escape HTML special characters for system info values
    $escapedValue = [System.Security.SecurityElement]::Escape($SystemInfo[$key].ToString())
    $html += "<tr><th>$key</th><td>$escapedValue</td></tr>"
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
        $resultText -eq "Not Installed" -or
        $resultText -eq "Not Detected" -or
        $resultText -eq "Not Activated" -or
        $resultText -eq "Not Present" -or
        $resultText -like "*Failed*" -or
        $resultText -like "Service Stopped*" -or
        $resultText -like "Service Disabled*" -or
        $resultText -like "Service Not Found*" -or
        $resultText -like "*EXPIRED*" -or
        $resultText -like "[-] Missing*"
        ) {
        $resultClass = "status-negative"
    }
    # 2. Error results (Grey) - Check for explicit "Error:" prefix
    elseif ($resultText -like "Error:*") {
        $resultClass = "status-error"
    }
    # 3. Warning results (Yellow/Orange)
    elseif ($resultText -like "*Encryption In Progress*" -or # Specific warning for BitLocker
            $resultText -like "*Warning*" -or
            $resultText -like "*Partial*" -or
            $resultText -like "*Expires Soon*" -or
            $resultText -like "Some Corporate Certificates Missing*"
            ) {
        $resultClass = "status-warning"
    }
    # 4. Positive results (Green) - Check these after all negative/error/warning
    elseif ($resultText -eq "True" -or
            $resultText -like "*Installed (v*" -or
            $resultText -eq "Installed" -or
            $resultText -like "*Success*" -or
            $resultText -like "*Enabled*" -or
            $resultText -like "*Activated*" -or
            $resultText -like "*Present (Device:*" -or
            $resultText -eq "Present" -or
            $resultText -like "*Ping Successful*" -or
            $resultText -like "Service Running*" -or
            $resultText -like "[+] Found:*" -or
            $resultText -like "All Required Corporate Certificates Found*"
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

try {
    $html | Out-File $ReportFile -Encoding utf8
    Write-Host "Validation complete. Report saved to $ReportFile" -ForegroundColor Green
    Invoke-Item $ReportFile # Open the report automatically
} catch {
    Write-Error "Failed to save or open report file '$ReportFile': $($_.Exception.Message)"
}
```
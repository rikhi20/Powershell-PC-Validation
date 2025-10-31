# ==========================================
# PC Validation Script Beta 0.8
# ==========================================

Clear-Host
Write-Host "🔍 Starting PC Validation..." -ForegroundColor Cyan

$global:step = 0
$global:totalSteps = 0

function Run-Check($category, $name, $action) {
    $global:step++
    try {
        $result = & $action
        Write-Host ("[{0}/{1}] {2} - {3}: {4}" -f $global:step, $global:totalSteps, $category, $name, $result) -ForegroundColor Green
    }
    catch {
        Write-Host ("[{0}/{1}] {2} - {3}: FAILED ({4})" -f $global:step, $global:totalSteps, $category, $name, $_.Exception.Message) -ForegroundColor Red
    }
}

# ------------------------------------------
# Count total checks (update this as needed)
# ------------------------------------------
$global:totalSteps = 3 + 5 + 5  # Windows Hello + BitLocker + Software Checks

# ==========================================
# SECTION 1 - WINDOWS HELLO VALIDATION
# ==========================================

Run-Check "Windows Hello" "PIN Activated" {
    $userSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    $registryPath = "HKLM:\SOFTWARE\Microsoft\PassportForWork\$userSID\NGC"

    # Method 1: Registry Check
    if (Test-Path $registryPath) {
        $keys = Get-ChildItem $registryPath -ErrorAction SilentlyContinue
        if ($keys) {
            return "Activated (Registry key found)"
        }
    }

    # Method 2: Fallback NGC folder check
    $ngcPath = "$env:LOCALAPPDATA\Microsoft\NGC"
    if (Test-Path $ngcPath) {
        return "Activated (NGC folder exists)"
    }

    return "Not Activated (No PIN setup found)"
}

Run-Check "Windows Hello" "Fingerprint Module" {
    $devices = Get-PnpDevice | Where-Object { $_.FriendlyName -match "Fingerprint" -and $_.Status -eq "OK" }
    if ($devices) {
        "Detected ($($devices.Count) device(s))"
    } else {
        "Not Detected"
    }
}

Run-Check "Windows Hello" "IR Camera" {
    $irCam = Get-PnpDevice | Where-Object { $_.FriendlyName -match "IR Camera" -and $_.Status -eq "OK" }
    if ($irCam) {
        "Detected ($($irCam.Count) device(s))"
    } else {
        "Not Detected"
    }
}

# ==========================================
# SECTION 2 - BITLOCKER VALIDATION
# ==========================================

Run-Check "BitLocker" "Protection Status" {
    $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
    if ($bitlockerVolumes) {
        $enabled = $bitlockerVolumes | Where-Object { $_.ProtectionStatus -eq "On" }
        if ($enabled) {
            "Enabled on $($enabled.Count) volume(s)"
        } else {
            "Not Enabled"
        }
    } else {
        "No BitLocker Volumes found"
    }
}

Run-Check "BitLocker" "Recovery Key Backup Check" {
    $recoveryKey = (Get-BitLockerVolume -ErrorAction SilentlyContinue | Select-Object -ExpandProperty KeyProtector -ErrorAction SilentlyContinue | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' })
    if ($recoveryKey) {
        "Recovery Key Exists"
    } else {
        "No Recovery Key Found"
    }
}

Run-Check "BitLocker" "TPM Status" {
    $tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction SilentlyContinue
    if ($tpm -and $tpm.IsEnabled_InitialValue -eq $true) {
        "TPM Enabled"
    } else {
        "TPM Not Enabled"
    }
}

Run-Check "BitLocker" "TPM Ready" {
    $tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction SilentlyContinue
    if ($tpm -and $tpm.IsActivated_InitialValue -eq $true) {
        "TPM Ready"
    } else {
        "TPM Not Ready"
    }
}

Run-Check "BitLocker" "Encryption Method" {
    $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
    if ($bitlockerVolumes) {
        $methods = $bitlockerVolumes | ForEach-Object { "$($_.MountPoint): $($_.EncryptionMethod)" }
        $methods -join ", "
    } else {
        "No Volumes Found"
    }
}

# ==========================================
# SECTION 3 - SOFTWARE VALIDATION
# ==========================================

$softwareChecks = @(
    @{ Name = "Google Chrome";      Search = @("Chrome") },
    @{ Name = "Microsoft Edge";     Search = @("msedge") },
    @{ Name = "Zoom";               Search = @("Zoom") },
    @{ Name = "Teams";              Search = @("Teams") },
    @{ Name = "LastPass";           Search = @("LastPass"); Exec = @(
        "$env:LOCALAPPDATA\LastPass\LastPass.exe",
        "$env:ProgramFiles\LastPass\LastPass.exe",
        "$env:ProgramFiles(x86)\LastPass\LastPass.exe"
    ) }
)

foreach ($app in $softwareChecks) {
    Run-Check "Software" $app.Name {
        $found = $false

        # Check Registry
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        )
        foreach ($path in $regPaths) {
            $apps = Get-ChildItem $path -ErrorAction SilentlyContinue | Get-ItemProperty -ErrorAction SilentlyContinue
            if ($apps | Where-Object { $_.DisplayName -match $app.Search }) {
                $found = $true
                break
            }
        }

        # Check Executables
        if (-not $found -and $app.Exec) {
            foreach ($exe in $app.Exec) {
                if (Test-Path $exe) {
                    $found = $true
                    break
                }
            }
        }

        if ($found) { "Installed" } else { "Not Installed" }
    }
}

# ==========================================
# END OF SCRIPT
# ==========================================

Write-Host "`n✅ Validation Completed! ($step checks done)" -ForegroundColor Cyan

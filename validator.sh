#!/bin/bash

# ======================================
# Mac Validation Script
# Version 0.2 Beta
# $(date)
# ======================================

REPORT="$HOME/Desktop/Mac_Validation_Report.html"
> "$REPORT"  # Clear previous report

clear
echo "======================================"
echo "   Mac Validation Utility"
echo "   Version 0.5 Beta"
echo "   Date: $(date)"
echo "======================================"
echo ""

# -------------------------------
# Simplified progress simulation
# -------------------------------
progress() {
    duration=$1
    for ((elapsed=1; elapsed<=duration; elapsed++)); do
        done=$elapsed
        remaining=$((duration - elapsed))
        bar_done=$(printf '▇%.0s' $(seq 1 $done))
        bar_remain=$(printf ' %.0s' $(seq 1 $remaining))
        percent=$(( (elapsed*100)/duration ))
        printf "\rProgress : [%s%s] %s%%" "$bar_done" "$bar_remain" "$percent"
        sleep 0.05
    done
    echo ""
}

# Function to get a more human-readable model name
get_human_readable_model() {
    local model_id=$(sysctl -n hw.model)
    local cpu_brand=$(sysctl -n machdep.cpu.brand_string)

    local marketing_name=""
    local chip_name=""

    # Extract chip name (e.g., "M1", "M2 Pro", "Intel Core i7")
    if [[ "$cpu_brand" =~ Apple\ (M[0-9].*) ]]; then
        chip_name="${BASH_REMATCH[1]}"
    elif [[ "$cpu_brand" =~ Intel\ (Core.*) ]]; then
        chip_name="${BASH_REMATCH[1]}"
    else
        chip_name="$cpu_brand" # Fallback if not Apple Silicon or common Intel
    fi

    # Basic mapping for common Apple product lines based on model identifier prefix
    case "$model_id" in
        MacBookAir*)
            marketing_name="MacBook Air"
            ;;
        MacBookPro*)
            marketing_name="MacBook Pro"
            ;;
        Macmini*)
            marketing_name="Mac mini"
            ;;
        iMac*)
            marketing_name="iMac"
            ;;
        MacPro*)
            marketing_name="Mac Pro"
            ;;
        MacStudio*)
            marketing_name="Mac Studio"
            ;;
        VirtualMac*) # For VMs
            marketing_name="Virtual Mac"
            ;;
        # Add specific model identifiers here if you know what they map to.
        # Example: if Mac16,8 is a new iMac:
        # Mac16,8)
        #    marketing_name="iMac"
        #    ;;
        *)
            # If we don't have a specific marketing name, use a generic one
            # and rely on the model ID and chip for identification.
            if [[ "$model_id" =~ ^(MacBook|Mac)[a-zA-Z]* ]]; then
                marketing_name="Apple Mac" # Generic for unknown MacBooks/Macs
            else
                marketing_name="Unknown Mac Model"
            fi
            ;;
    esac

    # Combine them
    # Prioritize chip if it's Apple Silicon for clarity
    if [[ "$chip_name" =~ Apple\ M[0-9] ]]; then
        echo "$marketing_name with $chip_name ($model_id)"
    else
        echo "$marketing_name ($model_id) with $chip_name"
    fi
}


echo "Collecting system information..."
progress 20
echo ""

# -------------------------------
# HTML Header
# -------------------------------
cat <<EOF >> "$REPORT"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Mac Validation Report</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; }
h2 { color: #2a7ae2; }
table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #2a7ae2; color: white; }
tr:nth-child(even) { background-color: #f2f2f2; }
.success { color: green; font-weight: bold; }
.failure { color: red; font-weight: bold; }
</style>
</head>
<body>
<h1>Mac Validation Report</h1>
<p>Date: $(date)</p>
EOF

# -------------------------------
# System Info
# -------------------------------
# Get OS product version and build version
OS_PRODUCT_NAME=$(sw_vers -productName) # e.g., macOS
OS_PRODUCT_VERSION=$(sw_vers -productVersion) # e.g., 14.0
OS_BUILD_VERSION=$(sw_vers -buildVersion) # e.g., 23A344

# Get OS marketing name (Sonoma, Ventura, etc.)
OS_MARKETING_NAME=""
case "$OS_PRODUCT_VERSION" in
    15.*) OS_MARKETING_NAME="Sequoia";; # macOS 15 (Sequoia)
    14.*) OS_MARKETING_NAME="Sonoma";;
    13.*) OS_MARKETING_NAME="Ventura";;
    12.*) OS_MARKETING_NAME="Monterey";;
    11.*) OS_MARKETING_NAME="Big Sur";;
    10.15*) OS_MARKETING_NAME="Catalina";;
    10.14*) OS_MARKETING_NAME="Mojave";;
    10.13*) OS_MARKETING_NAME="High Sierra";;
    *) OS_MARKETING_NAME="Unknown macOS";;
esac

cat <<EOF >> "$REPORT"
<h2>System Information</h2>
<table>
<tr><th>Item</th><th>Value</th></tr>
<tr><td>Hostname</td><td>$(hostname)</td></tr>
<tr><td>OS Version</td><td>$OS_PRODUCT_NAME $OS_MARKETING_NAME ($OS_PRODUCT_VERSION, build $OS_BUILD_VERSION)</td></tr>
<tr><td>Model</td><td>$(get_human_readable_model)</td></tr>
<tr><td>Serial Number</td><td>$(system_profiler SPHardwareDataType | awk '/Serial/ {print $4}')</td></tr>
<tr><td>Processor</td><td>$(sysctl -n machdep.cpu.brand_string)</td></tr>
<tr><td>Cores</td><td>$(sysctl -n hw.ncpu)</td></tr>
<tr><td>Memory</td><td>$(($(sysctl -n hw.memsize)/1024/1024/1024)) GB</td></tr>
<tr><td>Disk</td><td>$(df -h / | awk 'NR==2 {print $2 " total, " $4 " free"}')</td></tr>
</table>
EOF

# -------------------------------
# Battery Info
# -------------------------------
BATTERY_INFO=$(pmset -g batt | grep -E "InternalBattery|Battery")
cat <<EOF >> "$REPORT"
<h2>Battery Information</h2>
<pre>$BATTERY_INFO</pre>
EOF

# -------------------------------
# Security Info
# -------------------------------
GATEKEEPER=$(spctl --status)
SIP=$(csrutil status 2>/dev/null || echo 'Not available (must be run in recovery)')
FILEVAULT=$(fdesetup status)
cat <<EOF >> "$REPORT"
<h2>Security Checks</h2>
<table>
<tr><th>Item</th><th>Status</th></tr>
<tr><td>Gatekeeper</td><td>$GATEKEEPER</td></tr>
<tr><td>SIP Status</td><td>$SIP</td></tr>
<tr><td>FileVault</td><td>$FILEVAULT</td></tr>
</table>
EOF

# -------------------------------
# Intranet Connectivity
# -------------------------------
PING_HOST="intra.rakuten.co.jp"
if ping -c 2 -W 2 "$PING_HOST" >/dev/null 2>&1; then
    INTRA_STATUS="<span class='success'>Reachable ✅</span>"
else
    INTRA_STATUS="<span class='failure'>Not Reachable ❌</span>"
fi

cat <<EOF >> "$REPORT"
<h2>Intranet Connectivity</h2>
<table>
<tr><th>Host</th><th>Status</th></tr>
<tr><td>$PING_HOST</td><td>$INTRA_STATUS</td></tr>
</table>
EOF

# -------------------------------
# Application Checks
# -------------------------------
# List of applications to check for existence in /Applications (or common subdirectories)
APPS=(
    "Google Chrome.app"
    "Microsoft Outlook.app"
    "Microsoft Teams.app"
    "Slack.app"
    "Zoom.us.app"
    "Self Service.app"       # Jamf Self Service
    "Microsoft Word.app"     # Microsoft Office
    "Microsoft PowerPoint.app" # Microsoft Office
    "Microsoft Excel.app"    # Microsoft Office
    "Jamf Connect.app"       # Jamf Connect
    "Falcon.app"             # CrowdStrike Falcon (common app name)
    "CyberArk EPM.app"       # CyberArk (common app name, may vary)
    "LastPass.app"           # LastPass Desktop App
    "Firefox.app"            # Mozilla Firefox
)

cat <<EOF >> "$REPORT"
<h2>Application Checks</h2>
<table>
<tr><th>Application</th><th>Status</th></tr>
EOF

for app in "${APPS[@]}"; do
    if [ -d "/Applications/$app" ]; then
        STATUS="<span class='success'>Installed ✅</span>"
    else
        STATUS="<span class='failure'>Missing ❌</span>"
    fi
    echo "<tr><td>$app</td><td>$STATUS</td></tr>" >> "$REPORT"
done

# --- Specific Zscaler Check ---
# Define the exact path to Zscaler.app based on your clarification
ZSCALER_APP_PATH="/Applications/Zscaler/Zscaler.app"
ZSCALER_PROCESS_NAME="Zscaler" # Common process name for Zscaler

ZSCALER_STATUS="<span class='failure'>Not Found ❌</span>"
if [ -d "$ZSCALER_APP_PATH" ]; then
    ZSCALER_STATUS="<span class='success'>Installed (App) ✅</span>"
    # Further check if the process is running
    if pgrep -xq "$ZSCALER_PROCESS_NAME"; then
        ZSCALER_STATUS="<span class='success'>Installed & Running ✅</span>"
    else
        ZSCALER_STATUS="<span class='failure'>Installed (App), but not Running ⚠️</span>"
    fi
fi
echo "<tr><td>Zscaler</td><td>$ZSCALER_STATUS</td></tr>" >> "$REPORT"

# -------------------------------
# HTML Footer
# -------------------------------
cat <<EOF >> "$REPORT"
</table>
<p>Validation Complete ✅</p>
</body>
</html>
EOF

echo "Validation Complete ✅"
echo "HTML report saved to $REPORT"

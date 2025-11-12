#!/bin/bash

# ======================================
# Mac Validation Script
# Version 2.5 Beta
# Date: $(date)
# ======================================

# Get Serial Number for report name
MAC_SERIAL=$(system_profiler SPHardwareDataType | awk '/Serial/ {print $4}' | tr -d ' ')
REPORT="$HOME/Desktop/${MAC_SERIAL}_validation.html"

> "$REPORT"  # Clear previous report

clear
echo "======================================"
echo "   TST Mac Validation Utility"
echo "   Version 2.5 Beta"
echo "   Date: $(date)"
echo "======================================"
echo ""

# -------------------------------
# Simplified progress simulation
# -------------------------------
progress() {
    local duration=$1
    for ((elapsed=1; elapsed<=duration; elapsed++)); do
        local done=$elapsed
        local remaining=$((duration - elapsed))
        local bar_done=$(printf '▇%.0s' $(seq 1 $done))
        local bar_remain=$(printf ' %.0s' $(seq 1 $remaining))
        local percent=$(( (elapsed*100)/duration ))
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

    if [[ "$cpu_brand" =~ Apple\ (M[0-9].*) ]]; then
        chip_name="${BASH_REMATCH[1]}"
    elif [[ "$cpu_brand" =~ Intel\ (Core.*) ]]; then
        chip_name="${BASH_REMATCH[1]}"
    else
        chip_name="$cpu_brand"
    fi

    case "$model_id" in
        MacBookAir*) marketing_name="MacBook Air";;
        MacBookPro*) marketing_name="MacBook Pro";;
        Macmini*) marketing_name="Mac mini";;
        iMac*) marketing_name="iMac";;
        MacPro*) marketing_name="Mac Pro";;
        MacStudio*) marketing_name="Mac Studio";;
        VirtualMac*) marketing_name="Virtual Mac";;
        *)
            if [[ "$model_id" =~ ^(MacBook|Mac)[a-zA-Z]* ]]; then
                marketing_name="Apple Mac"
            else
                marketing_name="Unknown Mac Model"
            fi
            ;;
    esac

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
# HTML Header (Modern Crimson Red & White Theme)
# -------------------------------
cat <<EOF >> "$REPORT"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mac Validation Report - $MAC_SERIAL</title>
<style>
body {
    font-family: 'Arial', sans-serif;
    margin: 0;
    padding: 20px;
    background-color: #f8f8f8; /* Very light grey background */
    color: #333; /* Dark grey text */
}
.container {
    max-width: 900px;
    margin: 0 auto;
    background-color: #fff;
    padding: 30px;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
}
h1 {
    color: #BF0000; /* Crimson Red */
    font-size: 2.2em;
    border-bottom: 2px solid #BF0000;
    padding-bottom: 10px;
    margin-bottom: 20px;
    text-align: center;
}
h2 {
    color: #BF0000; /* Crimson Red */
    font-size: 1.6em;
    margin-top: 30px; /* Increased margin-top for better separation */
    margin-bottom: 15px;
    padding-bottom: 5px;
    border-bottom: 1px solid #eee;
}
table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 20px; /* Added margin-bottom for separation after tables */
    background-color: #fff;
    border-radius: 5px;
    overflow: hidden; /* Ensures rounded corners apply to borders */
}
th, td {
    border: 1px solid #e0e0e0; /* Lighter border for tables */
    padding: 12px 15px;
    text-align: left;
}
th {
    background-color: #BF0000; /* Crimson Red */
    color: white;
    font-weight: bold;
    text-transform: uppercase;
    font-size: 0.9em;
}
tr:nth-child(even) {
    background-color: #f9f9f9; /* Slightly off-white for even rows */
}
tr:hover {
    background-color: #f0f0f0; /* Subtle hover effect */
}
.success { color: #28a745; font-weight: bold; } /* Green */
.failure { color: #dc3545; font-weight: bold; } /* Red */
.warning { color: #ffc107; font-weight: bold; } /* Orange/Yellow */
pre {
    background-color: #f4f4f4;
    border: 1px solid #ddd;
    padding: 10px;
    border-radius: 4px;
    overflow-x: auto;
    white-space: pre-wrap; /* Wrap long lines */
    word-wrap: break-word; /* Break words if necessary */
    margin-bottom: 20px; /* Added margin-bottom for separation after preformatted text */
}
p {
    line-height: 1.6;
}
</style>
</head>
<body>
<div class="container">
<h1>Mac Validation Report for $MAC_SERIAL</h1>
<p><strong>Generated On:</strong> $(date)</p>
EOF

# -------------------------------
# System Info
# -------------------------------
OS_PRODUCT_NAME=$(sw_vers -productName)
OS_PRODUCT_VERSION=$(sw_vers -productVersion)
OS_BUILD_VERSION=$(sw_vers -buildVersion)

OS_MARKETING_NAME=""
case "$OS_PRODUCT_VERSION" in
    26.*) OS_MARKETING_NAME="Tahoe";;
    15.*) OS_MARKETING_NAME="Sequoia";;
    14.*) OS_MARKETING_NAME="Sonoma";;
    13.*) OS_MARKETING_NAME="Ventura";;
    12.*) OS_MARKETING_NAME="Monterey";;
    11.*) OS_MARKETING_NAME="Big Sur";;
    10.15*) OS_MARKETING_NAME="Catalina";;
    10.14*) OS_MARKETING_NAME="Mojave";;
    10.13*) OS_MARKETING_NAME="High Sierra";;
    *) OS_MARKETING_NAME="Unknown macOS";;
esac

# Get main display resolution
MAIN_DISPLAY_RESOLUTION=$(system_profiler SPDisplaysDataType 2>/dev/null | awk '/Resolution:/ {print $2 "x" $4; exit}')
if [ -z "$MAIN_DISPLAY_RESOLUTION" ]; then
    MAIN_DISPLAY_RESOLUTION="N/A"
fi


cat <<EOF >> "$REPORT"
<h2>System Information</h2>
<table>
<tr><th>Item</th><th>Value</th></tr>
<tr><td>Hostname</td><td>$(hostname)</td></tr>
<tr><td>OS Version</td><td>$OS_PRODUCT_NAME $OS_MARKETING_NAME ($OS_PRODUCT_VERSION, build $OS_BUILD_VERSION)</td></tr>
<tr><td>Model</td><td>$(get_human_readable_model)</td></tr>
<tr><td>Serial Number</td><td>$MAC_SERIAL</td></tr>
<tr><td>Processor</td><td>$(sysctl -n machdep.cpu.brand_string)</td></tr>
<tr><td>Cores</td><td>$(sysctl -n hw.ncpu)</td></tr>
<tr><td>Memory</td><td>$(($(sysctl -n hw.memsize)/1024/1024/1024)) GB</td></tr>
<tr><td>Disk</td><td>$(df -h / | awk 'NR==2 {print $2 " total, " $4 " free"}')</td></tr>
<tr><td>Main Display Resolution</td><td>$MAIN_DISPLAY_RESOLUTION</td></tr>
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
APP_LIST=(
    "Google Chrome.app"
    "Microsoft Outlook.app"
    "Microsoft Teams.app"
    "Slack.app"
    "Zoom.us.app"
    "Self Service+.app"
    "Microsoft Word.app"
    "Microsoft PowerPoint.app"
    "Microsoft Excel.app"
    "Jamf Connect.app"
    "Falcon.app"
    "CyberArk EPM.app"
    "LastPass.app"
    "Firefox.app"
    "Okta Verify.app"
)

cat <<EOF >> "$REPORT"
<h2>Application Checks</h2>
<table>
<tr><th>Application</th><th>Status</th><th>Version</th></tr>
EOF

for app_full_name in "${APP_LIST[@]}"; do
    app_display_name="${app_full_name%.app}"
    APP_PATH="/Applications/$app_full_name"
    APP_VERSION="N/A"
    STATUS="<span class='failure'>Missing ❌</span>"

    if [ -d "$APP_PATH" ]; then
        STATUS="<span class='success'>Installed ✅</span>"
        # Try to get version using mdls
        MDLS_VERSION=$(mdls -name kMDItemVersion -raw "$APP_PATH" 2>/dev/null)
        if [ -n "$MDLS_VERSION" ]; then
            APP_VERSION="$MDLS_VERSION"
        else
            # Fallback for apps that might not have kMDItemVersion (e.g., some simple apps)
            INFO_PLIST_VERSION=$(defaults read "$APP_PATH/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null)
            if [ -n "$INFO_PLIST_VERSION" ]; then
                APP_VERSION="$INFO_PLIST_VERSION"
            fi
        fi
    fi
    echo "<tr><td>$app_display_name</td><td>$STATUS</td><td>$APP_VERSION</td></tr>" >> "$REPORT"
done

# --- Specific Zscaler Check ---
ZSCALER_APP_PATH="/Applications/Zscaler/Zscaler.app"
ZSCALER_PROCESS_NAME="Zscaler"
ZSCALER_VERSION="N/A"

ZSCALER_STATUS="<span class='failure'>Not Found ❌</span>"
if [ -d "$ZSCALER_APP_PATH" ]; then
    ZSCALER_STATUS="<span class='success'>Installed (App) ✅</span>"
    # Get Zscaler version
    MDLS_VERSION=$(mdls -name kMDItemVersion -raw "$ZSCALER_APP_PATH" 2>/dev/null)
    if [ -n "$MDLS_VERSION" ]; then
        ZSCALER_VERSION="$MDLS_VERSION"
    else
        INFO_PLIST_VERSION=$(defaults read "$ZSCALER_APP_PATH/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null)
        if [ -n "$INFO_PLIST_VERSION" ]; then
            ZSCALER_VERSION="$INFO_PLIST_VERSION"
        fi
    fi

    if pgrep -xq "$ZSCALER_PROCESS_NAME"; then
        ZSCALER_STATUS="<span class='success'>Installed & Running ✅</span>"
    else
        ZSCALER_STATUS="<span class='warning'>Installed (App), but not Running ⚠️</span>"
    fi
fi
echo "<tr><td>Zscaler</td><td>$ZSCALER_STATUS</td><td>$ZSCALER_VERSION</td></tr>" >> "$REPORT"


# -------------------------------
# macOS Update Check
# -------------------------------
cat <<EOF >> "$REPORT"
<h2>macOS Update Status</h2>
<table>
<tr><th>Item</th><th>Status</th></tr>
EOF

# Perform the software update check
SOFTWARE_UPDATE_CHECK=$(softwareupdate --list 2>&1)

if echo "$SOFTWARE_UPDATE_CHECK" | grep -q "No new software available."; then
    UPDATE_STATUS="<span class='success'>No updates available ✅</span>"
elif echo "$SOFTWARE_UPDATE_CHECK" | grep -q "Software Update found the following new software:"; then
    UPDATE_STATUS="<span class='warning'>Updates available ⚠️</span><pre>$SOFTWARE_UPDATE_CHECK</pre>"
else
    UPDATE_STATUS="<span class='failure'>Could not determine update status ❌</span><pre>$SOFTWARE_UPDATE_CHECK</pre>"
fi

echo "<tr><td>macOS Updates</td><td>$UPDATE_STATUS</td></tr>" >> "$REPORT"

cat <<EOF >> "$REPORT"
</table>
EOF


# -------------------------------
# HTML Footer
# -------------------------------
cat <<EOF >> "$REPORT"
<p>Validation Complete ✅</p>
</div> <!-- Close container -->
</body>
</html>
EOF

echo "Validation Complete ✅"
echo "HTML report saved to $REPORT"

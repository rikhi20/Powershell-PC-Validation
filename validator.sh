

# ======================================
#  Mac Validation Script
#  Version 0.5 Beta
#  $(date)
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
cat <<EOF >> "$REPORT"
<h2>System Information</h2>
<table>
<tr><th>Item</th><th>Value</th></tr>
<tr><td>Hostname</td><td>$(hostname)</td></tr>
<tr><td>OS Version</td><td>$(sw_vers -productName) $(sw_vers -productVersion) ($(sw_vers -buildVersion))</td></tr>
<tr><td>Model</td><td>$(sysctl -n hw.model)</td></tr>
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
APPS=(
    "Google Chrome.app"
    "Microsoft Outlook.app"
    "Microsoft Teams.app"
    "Slack.app"
    "Zoom.us.app"
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

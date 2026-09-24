#!/usr/bin/env bash
# Regenerate docs/screenshots/*.png from a demo environment with headless Chrome.
#   python tools/demo_seed.py /tmp/demo.db
#   SIM_DB=/tmp/demo.db SIM_AUTOLOGIN=1 python app.py &
#   bash tools/screenshots.sh [base-url]
set -euo pipefail
BASE="${1:-http://localhost:8080}"
OUT="$(cd "$(dirname "$0")/.." && pwd)/docs/screenshots"
CHROME="$(command -v google-chrome || command -v chromium || command -v chromium-browser)"
mkdir -p "$OUT"

shot() {  # shot <file> <path> <height>
  "$CHROME" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --window-size=1440,"$3" --virtual-time-budget=3000 --screenshot="$OUT/$1.png" "$BASE$2" 2>/dev/null
  echo "  $1.png"
}

# Instance id for a given Name, from the reachability source list.
iid() { curl -s "$BASE/network/reachability" | grep -o "value=\"i-[0-9a-f]*\"[^>]*>$1 " | head -1 | cut -d'"' -f2; }
APP=$(iid app-1)
WEB=$(iid web-1)
FN=$(curl -s "$BASE/lambda" | grep -o 'href="/lambda/[0-9]*"' | head -1 | cut -d'"' -f2)

shot dashboard /dashboard 1180
shot vpc-console /network 1700
shot reachability "/network/reachability?source=$APP&destination=internet&protocol=tcp&port=443" 1150
shot reachability-blocked "/network/reachability?source=$WEB&destination=from-internet&protocol=tcp&port=22" 1150
shot architecture /architecture 1250
shot instance "/compute/instance/$APP" 1050
shot labs /labs 1350
shot lab-steps /labs/17 1000
shot activity /activity 1100
shot costs /costs 1150
shot terraform /export/terraform 1150
shot lambda "$FN" 1450

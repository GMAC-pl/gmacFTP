#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-/tmp/gmacftp-render-check}"
SCALE="${MACKFTP_RENDER_SCALE:-1}"

case "$SCALE" in
  1|2) ;;
  *) echo "ERROR: MACKFTP_RENDER_SCALE must be 1 or 2" >&2; exit 64 ;;
esac
EXPECTED_WIDTH=$((1180 * SCALE))
EXPECTED_HEIGHT=$((740 * SCALE))

rm -rf "$OUT"
mkdir -p "$OUT"

cd "$ROOT"
MACKFTP_RENDER_CHECK=1 cargo build --locked --example ui_render_check

expected=(en pl manager editor ctx panel drag dark update)
for scenario in "${expected[@]}"; do
  target/debug/examples/ui_render_check "$OUT" "$scenario"
  file="$OUT/gmacftp_render_${scenario}.png"
  test -s "$file"
  file "$file" | grep -q "PNG image data, $EXPECTED_WIDTH x $EXPECTED_HEIGHT, 8-bit/color RGBA"
done

test "$(find "$OUT" -maxdepth 1 -type f -name 'gmacftp_render_*.png' | wc -l | tr -d ' ')" -eq "${#expected[@]}"
echo "UI render check passed: ${#expected[@]} privacy-safe scenarios in $OUT"

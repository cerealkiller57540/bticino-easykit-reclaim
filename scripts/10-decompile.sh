#!/usr/bin/env bash
#
# 10-decompile.sh <app.apk> — decompile the companion app to readable Java with jadx.
#
# This is the backbone (section 2): almost every decision in this project comes from reading
# the decompiled call path — the SIP address format, the media directions, the static-ECDH
# requirement, and the fact that door-opening is a local SIP MESSAGE. Keep the output tree.
#
# Needs: jadx 1.5.x on PATH (or set JADX=/path/to/jadx), and a JDK 17.
#
set -euo pipefail

APK="${1:-}"
OUT="${OUT:-$PWD/jadx-out}"
JADX="${JADX:-jadx}"

[ -n "$APK" ] || { echo "usage: $0 <app.apk>   (pull it with: adb shell pm path <pkg> ; adb pull <path>)" >&2; exit 2; }
[ -f "$APK" ] || { echo "!!! no such file: $APK" >&2; exit 2; }
command -v "$JADX" >/dev/null 2>&1 || { echo "!!! jadx not found — install jadx 1.5.x or set JADX=/path/to/jadx" >&2; exit 2; }

# Two passes on purpose:
#   1) Java call path only (--no-res): faster and smaller, this is what you read most.
#   2) Resources into $OUT-res: you DO need res/raw/*.rc (linphonerc) — see the checklist below —
#      and --no-res would skip exactly that. Keeping them in a separate tree keeps pass 1 lean.
# --show-bad-code : keep going on the handful of obfuscated-Kotlin decompile errors.
echo "==> decompiling $APK (Java call path) -> $OUT"
"$JADX" --no-res --show-bad-code -j2 -d "$OUT" "$APK" || true   # jadx exits non-zero on benign decompile warnings

echo "==> extracting resources (for res/raw/*.rc) -> $OUT-res"
"$JADX" --no-src -d "$OUT-res" "$APK" || true   # resources only; --no-src skips the Java decompile

COUNT="$(find "$OUT/sources" -name '*.java' 2>/dev/null | wc -l || echo 0)"
[ "$COUNT" -gt 0 ] || { echo "!!! no .java produced — is this really the app APK?" >&2; exit 1; }

echo "    OK: $COUNT .java files in $OUT/sources   (resources in $OUT-res/resources)"
cat <<'EOF'

What to look for in the decompiled tree (section 2 explains why each matters):
  • the SIP account being built   — grep for the SIP user part, the proxy/registrar setup
  • the "see the hall" call        — a Linphone call with video RecvOnly + a custom SDP attribute
  • the "slide to open" action     — it builds a small JSON-RPC body and sends a SIP MESSAGE
  • res/raw/*.rc (linphonerc)      — transport, server-name verification, media-encryption policy
                                     (in the resources pass: $OUT-res/resources/res/raw/)

  Tip: grep -rniE 'register|proxy|message|jsonrpc|setStatus|ciphersuite|srtp' "$OUT/sources" | less
EOF

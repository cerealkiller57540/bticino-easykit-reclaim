#!/usr/bin/env bash
#
# 20-extract.sh <pkg> — drive the Frida identity capture (section 3).
#
# This is the ONE interactive step. There is no automating it: the app only decrypts its
# identity when it provisions, so you must clear its data and walk the pairing flow by hand
# while the hook is live. Everything on either side of this step is scripted.
#
# Recommended target: an Android Studio / SDK emulator with a *Google APIs* system image
# (rootable, Frida-friendly) — far easier than a rooted phone. Run adb + Frida on the host.
#
# Needs: adb and frida-tools on PATH, a frida-server running on the device/emulator.
#
set -euo pipefail

PKG="${1:-}"
HOOK="$(cd "$(dirname "$0")" && pwd)/20-dump-identity.js"

[ -n "$PKG" ] || { echo "usage: $0 <android.package.name>" >&2; exit 2; }
[ -f "$HOOK" ] || { echo "!!! hook script not found next to this one: $HOOK" >&2; exit 2; }
command -v adb   >/dev/null 2>&1 || { echo "!!! adb not found (Android platform-tools)" >&2; exit 2; }
command -v frida >/dev/null 2>&1 || { echo "!!! frida not found — pip install frida-tools" >&2; exit 2; }

echo "==> checking device / frida-server"
adb get-state >/dev/null 2>&1 || { echo "!!! no adb device — start your emulator (Google APIs image) or plug the phone" >&2; exit 1; }
frida-ps -U >/dev/null 2>&1    || { echo "!!! frida can't reach the device — is frida-server running on it?" >&2; exit 1; }

cat <<EOF

==> IMPORTANT, do this now so doFinal fires with the identity:
    1) Clear the app data so it re-provisions on next launch:
         adb shell pm clear $PKG
    2) This script will SPAWN the app under the hook (frida -f, not attach).
    3) When the app opens, WALK THE PAIRING / LOGIN FLOW by hand.
    4) Watch the output below: the EC private key, X.509 cert, CA chain and SIP params
       appear as 'doFinal DECRYPT' hex blocks. Carve them out (PEM/ASN.1/JSON).

    Keep the recovered material OUT of this repo — store it in a password manager (section 7).

Press Enter to spawn $PKG under the hook (Ctrl-C to stop)...
EOF
read -r _

echo "==> frida -U -f $PKG -l $HOOK --no-pause"
exec frida -U -f "$PKG" -l "$HOOK" --no-pause

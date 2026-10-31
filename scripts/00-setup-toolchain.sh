#!/usr/bin/env bash
#
# 00-setup-toolchain.sh — build the TLS/SIP toolchain this project needs.
#
# This is "the wall": a BTicino/Legrand EasyKit door station only speaks a handful of
# *static-ECDH* TLS cipher suites that modern OpenSSL has dropped. So you cannot use stock
# openssl / curl / Python ssl — you must build on mbedTLS 3.6.x (NOT 4.x, which dropped the
# suites too), then build PJSIP against *that* mbedTLS. This script does both, from source,
# in your home directory, touching nothing system-wide except apt packages.
#
# Tested versions (the ones that produced a real SIP REGISTER 200 against the door):
#   mbedTLS 3.6.7   ·   PJSIP (pjproject) 2.17
#
# Run it on Linux / WSL2 Ubuntu. It is idempotent-ish: re-running re-uses cloned trees.
#
set -euo pipefail

# --- knobs you may override via the environment ----------------------------------------
MBEDTLS_VERSION="${MBEDTLS_VERSION:-v3.6.7}"     # a tag in Mbed-TLS/mbedtls; MUST be 3.6.x
PJSIP_VERSION="${PJSIP_VERSION:-2.17}"           # a tag in pjsip/pjproject
WORK="${WORK:-$HOME/bticino-build}"              # where sources are cloned & built
PREFIX="${PREFIX:-$HOME/opt/mbedtls}"            # where mbedTLS is installed (prefix)
JOBS="${JOBS:-2}"                                # parallel build jobs (keep low on a laptop)

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m    OK: %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m!!! %s\033[0m\n' "$*" >&2; exit 1; }

# --- sanity: refuse a 4.x mbedTLS, that's the #1 way to waste an afternoon ---------------
case "$MBEDTLS_VERSION" in
  v3.6.*|3.6.*) : ;;
  *) die "MBEDTLS_VERSION='$MBEDTLS_VERSION' — this project needs 3.6.x. 4.x dropped the static-ECDH suites the door requires." ;;
esac

say "0) apt dependencies"
sudo apt-get update
sudo apt-get install -y build-essential cmake git python3 pkg-config
ok "build tools present"

mkdir -p "$WORK"
cd "$WORK"

# --- mbedTLS ----------------------------------------------------------------------------
say "1) mbedTLS $MBEDTLS_VERSION — clone + build (with sample programs)"
if [ ! -d mbedtls ]; then
  git clone --depth 1 --branch "$MBEDTLS_VERSION" --recurse-submodules \
    https://github.com/Mbed-TLS/mbedtls.git
fi
cd mbedtls
# ENABLE_PROGRAMS=ON so we also get ssl_client2, the handshake prover used by 30-prove-handshake.sh
cmake -B build -DENABLE_PROGRAMS=ON -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX="$PREFIX"
cmake --build build -j "$JOBS"
cmake --install build --prefix "$PREFIX"
[ -x build/programs/ssl/ssl_client2 ] || die "ssl_client2 did not build — check the output above"
ok "mbedTLS installed in $PREFIX ; ssl_client2 at $WORK/mbedtls/build/programs/ssl/ssl_client2"
cd "$WORK"

# --- PJSIP against that mbedTLS ---------------------------------------------------------
say "2) PJSIP $PJSIP_VERSION — clone + configure AGAINST the mbedTLS above"
if [ ! -d pjproject ]; then
  git clone --depth 1 --branch "$PJSIP_VERSION" https://github.com/pjsip/pjproject.git
fi
cd pjproject
# The -I/-L are NOT optional: without them ./configure looks in /usr/local and reports
# "No MbedTLS libraries found", silently falling back and leaving you behind the cipher wall.
./configure \
  --with-mbedtls="$PREFIX" \
  CFLAGS="-fPIC -I$PREFIX/include" \
  LDFLAGS="-L$PREFIX/lib"
# Confirm configure actually SELECTED mbedTLS before spending minutes compiling.
if ! grep -q -i 'mbedtls' config.log 2>/dev/null; then
  die "configure did not pick up mbedTLS — re-read the ./configure output; the -I/-L paths must point at $PREFIX"
fi
make dep
make -j "$JOBS"
PJSUA="$(find pjsip-apps/bin -name 'pjsua*' -type f | head -n1 || true)"
[ -n "$PJSUA" ] && [ -x "$PJSUA" ] || die "pjsua did not build — check the output above"
ok "PJSIP built ; pjsua at $WORK/pjproject/$PJSUA"

# --- how to check it's good -------------------------------------------------------------
say "DONE — the toolchain is built"
cat <<EOF

  mbedTLS prefix : $PREFIX
  ssl_client2    : $WORK/mbedtls/build/programs/ssl/ssl_client2
  pjsua          : $WORK/pjproject/$PJSUA

Next steps:
  • 10-decompile.sh <app.apk>   — read how the app talks to the door (section 2)
  • 20-extract.sh <pkg>         — pull the TLS identity out of the app  (section 3, interactive)
  • 30-prove-handshake.sh       — prove the mutual-TLS handshake        (section 5)
  • 40-register.sh              — get the SIP REGISTER 200              (section 6)

Export these so the later scripts find the binaries:
  export MBEDTLS_PREFIX="$PREFIX"
  export SSL_CLIENT2="$WORK/mbedtls/build/programs/ssl/ssl_client2"
  export PJSUA="$WORK/pjproject/$PJSUA"
EOF

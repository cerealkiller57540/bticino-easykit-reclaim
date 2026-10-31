#!/usr/bin/env bash
#
# 30-prove-handshake.sh — prove the mutual-TLS handshake to the door, TLS layer only (section 5).
#
# Before dragging a whole SIP stack in, confirm the hard part works: a static-ECDH, mutually
# authenticated TLS session to the door, using the identity recovered in section 3. If this
# succeeds, the cryptography is done; if it fails at "no shared cipher" you're on an OpenSSL
# build, not mbedTLS (section 4).
#
# You supply (never hard-code secrets — read them from your vault into these paths/vars):
#   DOOR_IP    the door station IP on your LAN
#   DOOR_PORT  the SIP-TLS port (commonly 5061)
#   CLIENT_CRT path to the recovered client certificate (PEM)
#   CLIENT_KEY path to the recovered EC private key (PEM)
#   SSL_CLIENT2 path to the ssl_client2 built by 00-setup-toolchain.sh
#
set -euo pipefail

DOOR_IP="${DOOR_IP:?set DOOR_IP to the door station LAN IP}"
DOOR_PORT="${DOOR_PORT:-5061}"
CLIENT_CRT="${CLIENT_CRT:?set CLIENT_CRT to your recovered client cert (PEM)}"
CLIENT_KEY="${CLIENT_KEY:?set CLIENT_KEY to your recovered EC private key (PEM)}"
SSL_CLIENT2="${SSL_CLIENT2:-$HOME/bticino-build/mbedtls/build/programs/ssl/ssl_client2}"

[ -x "$SSL_CLIENT2" ] || { echo "!!! ssl_client2 not found/executable at $SSL_CLIENT2 — run 00-setup-toolchain.sh (or set SSL_CLIENT2)" >&2; exit 2; }
[ -f "$CLIENT_CRT" ]  || { echo "!!! client cert not found: $CLIENT_CRT" >&2; exit 2; }
[ -f "$CLIENT_KEY" ]  || { echo "!!! client key not found: $CLIENT_KEY"  >&2; exit 2; }

echo "==> handshake to $DOOR_IP:$DOOR_PORT with the recovered client identity"
echo "    (auth_mode=none: we don't verify the server name — see the CN-mismatch note in section 6)"

# debug_level=2 prints the negotiated protocol + ciphersuite. mbedTLS auto-negotiates one of the
# door's four static-ECDH suites; no force_ciphersuite needed.
set +e
OUT="$("$SSL_CLIENT2" \
  server_addr="$DOOR_IP" server_port="$DOOR_PORT" \
  crt_file="$CLIENT_CRT" key_file="$CLIENT_KEY" \
  auth_mode=none debug_level=2 2>&1)"
RC=$?
set -e

echo "$OUT"

if echo "$OUT" | grep -qiE 'Ciphersuite is .*ECDH'; then
  CIPHER="$(echo "$OUT" | grep -iE 'Ciphersuite is' | head -n1 | sed 's/.*Ciphersuite is //')"
  echo
  echo "    OK: handshake completed — ciphersuite: $CIPHER"
  echo "    => static-ECDH + mutual-TLS + your recovered key all work. Proceed to 40-register.sh."
  exit 0
fi

echo
echo "!!! handshake did NOT complete. Most likely causes, in order:" >&2
echo "    • 'no shared cipher' / fails early  -> you're on an OpenSSL build, not mbedTLS 3.6.x (section 4)" >&2
echo "    • cert/key rejected                 -> wrong identity, or not the pair the door expects" >&2
echo "    • connection refused/timeout        -> wrong DOOR_IP/DOOR_PORT, or no LAN route to the door" >&2
exit "${RC:-1}"

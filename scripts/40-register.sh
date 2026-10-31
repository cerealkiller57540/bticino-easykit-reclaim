#!/usr/bin/env bash
#
# 40-register.sh — get a SIP REGISTER 200 OK from the door (section 6).
#
# Once 30-prove-handshake.sh is green, the TLS layer is solved. This drives a full SIP stack
# (pjsua, built against the same mbedTLS by 00-setup-toolchain.sh) to actually REGISTER the
# recovered account against the door. A "registration success" / "200 OK" here means you are
# a first-class SIP endpoint: you can receive the ring (section 9) and open the door (section 8).
#
# You supply (read secrets from your vault into these — never commit them):
#   DOOR_IP    the door station IP on your LAN
#   DOOR_PORT  the SIP-TLS port (commonly 5061)
#   SIP_USER   the SIP user part recovered from the app (the "diy" account)
#   SIP_DOMAIN the SIP domain the app registers to (from the app config, NOT the LAN IP)
#   SIP_PASS   the SIP password recovered in section 3
#   CLIENT_CRT path to the recovered client certificate (PEM)
#   CLIENT_KEY path to the recovered EC private key (PEM)
#   PJSUA      path to the pjsua binary built by 00-setup-toolchain.sh
#
# Single-AOR trap (section 8): the door accepts ONE registration per account. If your real
# handset / the app is still registered, the door may bounce this one. Only one client at a time.
#
set -euo pipefail

DOOR_IP="${DOOR_IP:?set DOOR_IP to the door station LAN IP}"
DOOR_PORT="${DOOR_PORT:-5061}"
SIP_USER="${SIP_USER:?set SIP_USER to the recovered SIP user part}"
SIP_DOMAIN="${SIP_DOMAIN:?set SIP_DOMAIN to the SIP domain from the app config}"
SIP_PASS="${SIP_PASS:?set SIP_PASS to the recovered SIP password}"
CLIENT_CRT="${CLIENT_CRT:?set CLIENT_CRT to your recovered client cert (PEM)}"
CLIENT_KEY="${CLIENT_KEY:?set CLIENT_KEY to your recovered EC private key (PEM)}"
PJSUA="${PJSUA:?set PJSUA to the pjsua binary (00-setup-toolchain.sh prints the path)}"

[ -x "$PJSUA" ]      || { echo "!!! pjsua not found/executable at $PJSUA — run 00-setup-toolchain.sh (or set PJSUA)" >&2; exit 2; }
[ -f "$CLIENT_CRT" ] || { echo "!!! client cert not found: $CLIENT_CRT" >&2; exit 2; }
[ -f "$CLIENT_KEY" ] || { echo "!!! client key not found: $CLIENT_KEY"  >&2; exit 2; }

echo "==> registering sip:$SIP_USER@$SIP_DOMAIN via $DOOR_IP:$DOOR_PORT (TLS)"
echo "    (no --tls-ca-file: the door's server cert CN does not match its LAN IP — section 6)"

# --registrar routes to the door's IP while the account identity stays sip:user@domain.
# --tls-cert-file / --tls-privkey-file : the client identity from section 3 (mutual TLS).
# NO --tls-ca-file / --tls-verify-server : the cert CN won't match the LAN IP; verifying would
#   fail the handshake for the wrong reason. We already proved the door is who it is in step 30.
# --auto-answer is deliberately absent: we only want the REGISTER here, not to pick up calls.
set +e
OUT="$(timeout 25 "$PJSUA" \
  --id="sip:$SIP_USER@$SIP_DOMAIN" \
  --registrar="sip:$DOOR_IP:$DOOR_PORT;transport=tls" \
  --realm='*' --username="$SIP_USER" --password="$SIP_PASS" \
  --use-tls --tls-cert-file="$CLIENT_CRT" --tls-privkey-file="$CLIENT_KEY" \
  --no-tcp --null-audio \
  --log-level=4 \
  --duration=1 2>&1 <<<$'\nq\n')"
RC=$?
set -e

echo "$OUT" | grep -iE 'registration (success|status)|SIP/2.0 (200|401|403|407|408|503)|registration failed' || true

if echo "$OUT" | grep -qiE 'registration success|SIP/2.0 200'; then
  echo
  echo "    OK: REGISTER 200 — you are a registered SIP endpoint on the door."
  echo "    => the identity is complete and accepted. You can now receive the ring (section 9)"
  echo "       and open the door with an out-of-dialog SIP MESSAGE from this endpoint (section 8)."
  exit 0
fi

echo
echo "!!! no 200 OK. Read the log above; common causes:" >&2
echo "    • 401/407 looping     -> wrong SIP_PASS, or wrong realm/username" >&2
echo "    • 403 / silent bounce -> single-AOR: another client is already registered (section 8)" >&2
echo "    • TLS error before SIP -> redo step 30; this is a crypto/identity problem, not SIP" >&2
echo "    • 408 timeout         -> wrong DOOR_IP/DOOR_PORT or no route" >&2
exit "${RC:-1}"

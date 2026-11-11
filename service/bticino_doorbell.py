#!/usr/bin/env python3
"""Always-on SIP endpoint for a BTicino EasyKit door station.

Stays registered (REGISTER) through pjsua (mbedTLS 3.6, static ECDH, mutual TLS) and
publishes "ring" on MQTT for every incoming INVITE, i.e. "someone rang". Home Assistant
creates the binary_sensor through MQTT discovery; off_delay brings it back to "off".

Two sources of secrets, the rest of the code is the same:
 - systemd service: read from $CREDENTIALS_DIRECTORY (TPM2-sealed, decrypted into a
   tmpfs by systemd) => no vault access needed, survives a reboot of the host;
 - bench (started by hand): read on demand through rbw.
In service mode the key and cert point straight at the credentials tmpfs; the pjsua
config file (which holds the SIP password) lives in RUNTIME_DIRECTORY (/run/bticino)
or /dev/shm, and is deleted on exit.

HA availability: "online" is published only once REGISTER has succeeded (otherwise HA
would show "available" while pjsua is not registered). A watchdog exits (systemd
restarts the service) if the endpoint never registers or durably loses its
registration, so an HA "unavailable" alert can fire.

Per-install identifiers (certificate CN, SIP domain, door station address, relay
deviceAddrs, MQTT broker, vault item names) are NOT in this file: they are read from
the site config, see _load_site() and site.example.json.
"""
import atexit
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import queue
import threading
import time

import paho.mqtt.client as mqtt

def _load_site():
    """Per-install identifiers, kept out of the code.
    Service: systemd credential "site" (LoadCredential=site:/etc/bticino/site.json).
    Bench: path in $BTCK_SITE. Missing or unreadable => immediate exit."""
    cred = os.environ.get("CREDENTIALS_DIRECTORY")
    path = os.path.join(cred, "site") if cred else os.environ.get("BTCK_SITE", "")
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        sys.exit("FATAL: cannot read site config (%s): %s" % (path or "BTCK_SITE empty", e))


SITE = _load_site()


# --- SIP identity (SIP_USER is the certificate CN) ---
SIP_USER = SITE["sip_user"]
SIP_DOMAIN = SITE["sip_domain"]
SIP_PROXY = SITE["sip_proxy"]
SIP_DIY = f"sip:diy@{SIP_DOMAIN}"       # MESSAGE recipient (see VctLinphoneService.O in the app)

VAULT_SIP = SITE["vault_sip"]
VAULT_MQTT = SITE["vault_mqtt"]

MQTT_HOST = SITE["mqtt_host"]
MQTT_PORT = int(SITE["mqtt_port"])
T_STATE = "bticino/sonnette/state"
T_AVAIL = "bticino/sonnette/availability"
T_DISCO = "homeassistant/binary_sensor/bticino_sonnette/config"
T_CMD   = "bticino/portier/cmd"        # door/gate command (must be NON-retained)
T_PHOTO = "bticino/portier/photo"      # base64 JPEG (retained -> last photo)
T_PHOTO_EVT = "bticino/portier/photo/event"  # NON-retained: triggers the automation
T_PHOTO_DISCO = "homeassistant/camera/bticino_photo/config"
T_CALL = "bticino/portier/appel"         # JSON outcome of the last call (retained)
T_CALL_DISCO = "homeassistant/sensor/bticino_appel/config"
# A ring that nobody answers ends by itself after 29.7 s (measured over 5 rings);
# answering on the indoor unit gives a CANCEL at ~18 s. Fallback only when the CANCEL has no Reason.
ANSWERED_MAX_S = 27.0
CALL_OUTCOMES = ["manque", "decroche_ailleurs", "repondu_poste"]
FFMPEG = "/usr/bin/ffmpeg"
# Relay deviceAddrs (one per target), from the site config.
OPEN_TARGETS = SITE["open_targets"]

# PATCHED binary, frozen (AVI rotation, one file per ring). Stable copy outside the build
# tree (a relink would overwrite the inode). sha256[:16] is checked at startup.
# -sendrecv binary: the outgoing "see the entrance" call offers m=video sendrecv (instead of
# forced recvonly). The door answers sendrecv -> the stream is ACTIVE, video arrives, the AVI
# fills, with NO firewall rule needed. Incoming rings behave as before: the auto-answer
# 183 + DEVADDR are injected on the OUTGOING offer only (btck_uas marks incoming UAS).
PJSUA = os.path.expanduser("~/bticino-proof/pjsua-btck-avi-sendrecv")
PJSUA_SHA16 = "83a40e4fec813b4d"
PJSUA_FALLBACK = os.path.expanduser(
    "~/bticino-proof/pjproject/pjsip-apps/bin/pjsua-x86_64-pc-linux-gnu"
)
CAPTURE_ON = False   # set to True by _resolve_pjsua() when the patched binary checks out
# /run/bticino as a service (RuntimeDirectory, deleted on exit); /dev/shm on the bench.
RUN_DIR = os.environ.get("RUNTIME_DIRECTORY", "/dev/shm/bticino")
CFG_PATH = os.path.join(RUN_DIR, "pjsua.cfg")

REG_TIMEOUT = 3600       # requested Expires; the door station may grant less
STARTUP_GRACE = 180.0    # grace period before concluding "cannot register"
DEBOUNCE_S = 8.0         # one INVITE + its retransmissions => a single publication

RING_RE = re.compile(
    r"Incoming call for account|Incoming Request msg INVITE|RX \d+ bytes Request msg INVITE"
)
REG_OK_RE = re.compile(r"registration success|200/REGISTER|200 \(Registration successful\)")
REG_IN_RE = re.compile(r"re-?register\w* in (\d+)", re.I)   # "will re-register in N seconds"
REG_FAIL_RE = re.compile(
    r"registration failed|SIP registration failed|Unable to register|registration.*status=[45]\d\d",
    re.I,
)
# Headers copied into OUR log (never the bodies: the SDP carries the SRTP keys).
HDR_RE = re.compile(r"(?:RX|TX) \d+ bytes|registration|Error|Incoming")
# Markers printed by the patched binary. Anchored on "HH:MM:SS.mmm ... pjsua_app.c ...";
# lock 1 (regex) + locks 2/3 in the handler (dirname + name + last START).
BTCK_AVI_RE = re.compile(
    r"^\d\d:\d\d:\d\d\.\d{3}\s+pjsua_app\.c\s+\.*"
    r"BTCK-AVI-(START|DONE) (\S+)\s*$"
)
BTCK_NAME_RE = re.compile(r"^rx_\d+_\d+\.avi$")
CANCEL_RE = re.compile(r"RX \d+ bytes Request msg CANCEL")
# RFC 3326: a forking proxy sets "Reason: SIP;cause=200" when another
# branch answered. Only the value is kept (To/From carry the CN).
REASON_RE = re.compile(r"^Reason:\s*(.{1,160})", re.I)
END_MSG = "--end msg--"

# --- Answering machine: picks up if nobody answered, plays the greeting, records ---
REP_DIR = os.path.expanduser("~/bticino-proof/repondeur")
REP_PLAY = REP_DIR + "/annonce_prod.wav"     # 16 kHz mono s16, silence at head and tail
REP_REC = os.path.join(RUN_DIR, "repondeur_rec.wav")   # ONE file for all calls
REP_ANSWER_S = 20.0
REP_MSG_S = 30.0
# The pjmedia WAV writer buffers up to 4000 bytes: they belong to the previous
# call and are flushed at the start of the next one -> skip them.
REP_SKIP_B = 4000
REP_MAX_REC = 64 * 1024 * 1024    # beyond this: exit while idle, systemd restarts (fresh file)
REP_FILTER = ("highpass=f=150,lowpass=f=3800,afftdn=nf=-40,"
              "dynaudnorm=f=150:g=15:p=0.95:m=30,loudnorm=I=-12:TP=-1")
T_REP_SET = "bticino/repondeur/set"
T_REP_STATE = "bticino/repondeur/state"      # retained: state restored on restart
T_REP_MSG = "bticino/repondeur/message"      # NON-retained: base64 ogg -> HA pyscript
T_REP_DISCO = "homeassistant/switch/bticino_repondeur/config"
REP_PORT_RE = re.compile(r"^Port #(\d+)\[")
# Temporary diagnostic: pjsua output logged during an answering-machine call.
# SIP/SDP excluded (SRTP keys), video renderer noise excluded, volume capped.
REP_DIAG = True
REP_DIAG_MAX = 500
REP_DIAG_SKIP = re.compile(r"vid_port|Unexpected frame|Video device id=|^[a-z]=|^[A-Za-z-]+: |^SIP/2\.0|^[A-Z]+ sips?:|inline:")
REP_OPTS = []
REP_PLAY_S = 0.0

# --- Live "see the entrance": OUTGOING call to the door station, stream pushed to go2rtc ---
# The outgoing call becomes current_call (ui_make_new_call passes &current_call), so "h"
# hangs up the live. The -sendrecv binary gets the video without any firewall rule.
# Refused while an incoming call / answering machine is active (the ring would become unreachable).
T_LIVE_SET = "bticino/live/set"
T_LIVE_STATE = "bticino/live/state"      # retained for HA; never read back here
T_LIVE_DISCO = "homeassistant/switch/bticino_live/config"
CALL_STALE_S = 300.0      # a call id with no new state for this long is a ghost
LIVE_MAX_S = 180.0        # hard cap on a live (hangs up even if nothing else closes it)
# pjsua call states (pjsua_app.c on_call_state): every state except DISCONNECTED goes
# through "Call N state changed to <STATE>"; the end through "Call N is DISCONNECTED [reason=...]".
CALL_STATE_RE = re.compile(r"Call (\d+) state changed to (\w+)")
CALL_DISC_RE = re.compile(r"Call (\d+) is DISCONNECTED")
# Frame selected by INDEX, not by seconds: the pjsua AVI DECLARES 15 fps but
# really encodes ~9 fps (268 frames for ~29.7 s), so "-ss <s>" does not land where
# you expect. Measured: "-ss 2.5" => frame ~37 = visitor already out of frame;
# frame 10 (~4 s after the 183) = visitor well framed. n starts at 0.
JPEG_FRAME = "10"
# Timing instrumentation (OFF by default: zero production impact). Set to "1" in
# the service environment for ONE measurement ring, then remove.
DEBUG_KEEP = os.environ.get("BTCK_DEBUG_KEEP", "") == "1"
FFPROBE = os.environ.get("BTCK_FFPROBE", "/usr/bin/ffprobe")
# Debug AVIs on DISK (not RUN_DIR = tmpfs, wiped on restart), keeps the last N.
DEBUG_DIR = os.environ.get("BTCK_DEBUG_DIR", os.path.expanduser("~/bticino-proof/avi_debug"))
DEBUG_KEEP_N = 10


_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)


def log(msg):
    # Masks any SRTP key (a=crypto ... inline:<base64>) before journald, then any
    # UUID: the live's outgoing INVITE (-sendrecv binary) carries a=DEVADDR:<uuid> and
    # the SIP domain is a uuid -> no door station address may reach the log.
    msg = re.sub(r"inline:[^\s|]+", "inline:<SRTP_KEY>", str(msg))
    msg = _UUID_RE.sub("<UUID>", msg)
    print(f"[bticino] {msg}", flush=True)


def rbw(*args):
    return subprocess.run(
        ["rbw", *args], check=True, capture_output=True, text=True
    ).stdout


def setup_devaddr_env():
    """Reads the door station deviceAddr from the systemd credential (LoadCredential,
    not sealed) and puts it in BTCK_DEVADDR BEFORE pjsua is spawned (never in argv ->
    not visible in ps / systemctl show). The -sendrecv binary injects it only on the
    OUTGOING offer (live). Failure is not fatal: live view is unavailable, the rest works."""
    cred = os.environ.get("CREDENTIALS_DIRECTORY")
    if not cred:
        log("live: no CREDENTIALS_DIRECTORY -> live unavailable (ring/photo OK)")
        return False
    path = os.path.join(cred, "devaddr")
    try:
        with open(path) as fh:
            val = fh.read().strip()
    except OSError as e:
        log(f"live: cannot read devaddr credential -> live unavailable ({e})")
        return False
    if not _UUID_RE.fullmatch(val):
        log(f"live: devaddr credential is not a UUID ({len(val)} chars) -> live unavailable")
        return False
    os.environ["BTCK_DEVADDR"] = val
    log("live: door station deviceAddr loaded (<UUID>) -> outgoing call armed")
    return True


def extract_pem(notes, begin, end, all_blocks=False):
    out, cur, cap = [], [], False
    for ln in notes.splitlines():
        s = ln.strip()
        if s == begin:
            cap, cur = True, [s]
        elif s == end and cap:
            cur.append(s)
            out.append("\n".join(cur))
            cap, cur = False, []
            if not all_blocks:
                break
        elif cap:
            cur.append(ln)
    return ("\n".join(out) + "\n") if out else ""


class State:
    """Shared by the read loop, the MQTT thread and the watchdog."""

    def __init__(self):
        self.lock = threading.Lock()
        self.registered = False
        self.ever = False
        self.last_reg = None
        self.started = time.monotonic()
        self.reg_interval = REG_TIMEOUT
        self.proc = None
        self.stdin_lock = threading.Lock()
        self.last_cmd = {}   # target -> monotonic() of the last send (toggle debounce)
        # --- Live "see the entrance" ---
        self.live_on = False        # live is requested/active (published as the switch)
        self.live_call = None       # call id of the current live call (None = none)
        self.live_alive = False     # True between the "m" and the live's DISCONNECTED
        self.live_cap = None        # LIVE_MAX_S cap Timer (cancel on exit)
        self.live_last = 0.0        # monotonic() of the last toggle (debounce)
        self.calls = {}             # live call id -> monotonic() of the last state seen
                                    # (guard: no live while a ring is up)


def load_vault():
    sip_pw = rbw("get", VAULT_SIP).strip()
    notes = json.loads(rbw("get", "--raw", VAULT_SIP))["notes"]
    key = extract_pem(
        notes, "-----BEGIN EC PRIVATE KEY-----", "-----END EC PRIVATE KEY-----"
    )
    crt = extract_pem(
        notes, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----",
        all_blocks=True,
    )
    if not key or not crt:
        log("FATAL: key or certificate not found in the vault notes")
        sys.exit(1)
    mqtt_raw = json.loads(rbw("get", "--raw", VAULT_MQTT))["data"]
    return sip_pw, key, crt, mqtt_raw["username"], mqtt_raw["password"]


def _resolve_pjsua():
    """Patched binary if present AND its sha matches, otherwise fallback (capture off)."""
    global PJSUA, CAPTURE_ON
    try:
        import hashlib
        with open(PJSUA, "rb") as fh:
            h = hashlib.sha256(fh.read()).hexdigest()[:16]
        if h == PJSUA_SHA16:
            CAPTURE_ON = True
            log(f"patched pjsua OK (sha {h}) -> photo capture enabled")
            try:  # ffmpeg extracts the JPEG; missing = no photo
                subprocess.run([FFMPEG, "-version"], capture_output=True, timeout=5)
                log("ffmpeg found (JPEG extraction OK)")
            except (OSError, subprocess.SubprocessError):
                log(f"WARNING ffmpeg missing/broken ({FFMPEG}) -> no photo will be produced")
            return
        log(f"WARNING pjsua sha={h} != {PJSUA_SHA16} -> fallback WITHOUT capture")
    except OSError as e:
        log(f"WARNING patched binary missing ({e}) -> fallback WITHOUT capture")
    PJSUA = PJSUA_FALLBACK
    CAPTURE_ON = False


def prepare_runtime():
    """Prepares RUN_DIR + the pjsua config file. Returns (mqtt_user, mqtt_pw)."""
    os.makedirs(RUN_DIR, exist_ok=True)
    os.chmod(RUN_DIR, 0o700)
    cred = os.environ.get("CREDENTIALS_DIRECTORY")
    if cred:
        log("secrets: systemd-creds (TPM2)")
        key_file = os.path.join(cred, "sip.key")
        crt_file = os.path.join(cred, "sip.crt")
        if not (os.path.exists(key_file) and os.path.exists(crt_file)):
            log("FATAL: credential sip.key/sip.crt missing")
            sys.exit(1)
        with open(os.path.join(cred, "sip.pw")) as fh:
            sip_pw = fh.read().strip()
        with open(os.path.join(cred, "mqtt.user")) as fh:
            mqtt_user = fh.read().strip()
        with open(os.path.join(cred, "mqtt.pw")) as fh:
            mqtt_pw = fh.read().strip()
    else:
        log("secrets: rbw (vault)")
        sip_pw, key, crt, mqtt_user, mqtt_pw = load_vault()
        key_file = os.path.join(RUN_DIR, "client.key")
        crt_file = os.path.join(RUN_DIR, "client.crt")
        with open(key_file, "w") as fh:
            fh.write(key)
        os.chmod(key_file, 0o600)
        with open(crt_file, "w") as fh:
            fh.write(crt)
        os.chmod(crt_file, 0o644)

    # photo capture flags: only when the patched binary is in place.
    # --auto-answer=183 is MANDATORY (otherwise no early media => no video).
    # vcapture=2/vrender=3 = Null capture / Null renderer.
    cap = [
        "--auto-answer=183",
        "--use-srtp=2", "--srtp-secure=1",
        "--video", "--vcapture-dev=2", "--vrender-dev=3",
        f"--rec-avi={os.path.join(RUN_DIR, 'rx.avi')}",
        "--rec-avi-size=200000000",   # BYTES (200 MB); 200 would mean 200 bytes = 0 frames
        "--auto-rec-avi",
        "--rec-avi-audio",            # PCM track of the call in the AVI (live audio)
    ] if CAPTURE_ON else []
    # SIP password in the config file (RUN_DIR, 600) => not in argv/ps
    cfg = "\n".join([
        f"--id sip:{SIP_USER}@{SIP_DOMAIN}",
        f"--registrar sip:{SIP_DOMAIN};transport=tls",
        f"--proxy sip:{SIP_PROXY};transport=tls;lr",
        "--realm *",
        f"--username {SIP_USER}",
        f"--password {sip_pw}",
        f"--tls-cert-file {crt_file}",
        f"--tls-privkey-file {key_file}",
        "--use-tls",
        "--null-audio",
        f"--reg-timeout {REG_TIMEOUT}",
        "--log-level 4",
        "--app-log-level 4",
        *cap,
        *REP_OPTS,
    ]) + "\n"
    with open(CFG_PATH, "w") as fh:
        fh.write(cfg)
    os.chmod(CFG_PATH, 0o600)
    return mqtt_user, mqtt_pw


def wipe():
    # Touches only RUN_DIR (never CREDENTIALS_DIRECTORY, read-only and managed by systemd).
    shutil.rmtree(RUN_DIR, ignore_errors=True)


def publish_discovery(cli):
    disco = {
        "name": "Sonnette BTicino locale",
        "unique_id": "bticino_sonnette_local",
        "state_topic": T_STATE,
        "payload_on": "ring",
        "off_delay": 8,
        "icon": "mdi:bell-ring",
        "availability_topic": T_AVAIL,
        "payload_available": "online",
        "payload_not_available": "offline",
        "device": {
            "identifiers": ["bticino_easykit_25"],
            "name": "Portier BTicino EasyKit",
            "manufacturer": "BTicino/Legrand",
            "model": "Door Entry EASY KIT",
        },
    }
    cli.publish(T_DISCO, json.dumps(disco), qos=1, retain=True)


def publish_camera(cli):
    """MQTT camera: HA shows the last JPEG published on T_PHOTO (same device).
    image_encoding=b64 -> the JPEG is published base64-encoded on the topic."""
    disco = {
        "name": "Photo portier",
        "unique_id": "bticino_photo_local",
        "topic": T_PHOTO,
        "image_encoding": "b64",
        "icon": "mdi:camera",
        "availability_topic": T_AVAIL,
        "payload_available": "online",
        "payload_not_available": "offline",
        "device": {
            "identifiers": ["bticino_easykit_25"],
            "name": "Portier BTicino EasyKit",
            "manufacturer": "BTicino/Legrand",
            "model": "Door Entry EASY KIT",
        },
    }
    cli.publish(T_PHOTO_DISCO, json.dumps(disco), qos=1, retain=True)


def publish_call_sensor(cli):
    """Enum sensor: outcome of the last call, attributes = duration/method/reason."""
    disco = {
        "name": "Dernier appel",
        "unique_id": "bticino_dernier_appel_local",
        "state_topic": T_CALL,
        "value_template": "{{ value_json.issue }}",
        "json_attributes_topic": T_CALL,
        "device_class": "enum",
        "options": CALL_OUTCOMES,
        "icon": "mdi:phone-incoming",
        "availability_topic": T_AVAIL,
        "payload_available": "online",
        "payload_not_available": "offline",
        "device": {
            "identifiers": ["bticino_easykit_25"],
            "name": "Portier BTicino EasyKit",
            "manufacturer": "BTicino/Legrand",
            "model": "Door Entry EASY KIT",
        },
    }
    cli.publish(T_CALL_DISCO, json.dumps(disco), qos=1, retain=True)


def classify_call(dur, reason):
    """-> (outcome, method). Reason wins; the duration is only a fallback."""
    if reason:
        r = reason.lower()
        if "cause=200" in r or "elsewhere" in r or "completed" in r:
            return "decroche_ailleurs", "reason"
        return "manque", "reason"
    return ("decroche_ailleurs" if dur < ANSWERED_MAX_S else "manque"), "duree"


def publish_call(cli, ring_wall, dur, reason):
    issue, methode = classify_call(dur, reason)
    payload = {
        "issue": issue,
        "methode": methode,
        "duree_s": round(dur, 1),
        "raison": reason or "",
        "debut": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ring_wall)),
    }
    cli.publish(T_CALL, json.dumps(payload), qos=1, retain=True)
    log(f"call: {issue} ({methode}, {dur:.1f} s, reason={reason or '-'})")


def publish_buttons(cli):
    """One MQTT button per relay: a pulse (command_topic=T_CMD, payload=target key).
    Same device as the doorbell -> entities grouped in HA."""
    base_dev = {
        "identifiers": ["bticino_easykit_25"],
        "name": "Portier BTicino EasyKit",
        "manufacturer": "BTicino/Legrand",
        "model": "Door Entry EASY KIT",
    }
    buttons = [
        ("portail", "Portail (impulsion)", "mdi:gate"),
        ("gache", "Gache (impulsion)", "mdi:door-open"),
        ("lumiere", "Lumiere escaliers", "mdi:lightbulb"),
    ]
    for key, name, icon in buttons:
        disco = {
            "name": name,
            "unique_id": f"bticino_{key}_local",
            "command_topic": T_CMD,
            "payload_press": key,
            "icon": icon,
            "availability_topic": T_AVAIL,
            "payload_available": "online",
            "payload_not_available": "offline",
            "device": base_dev,
        }
        topic = f"homeassistant/button/bticino_{key}/config"
        cli.publish(topic, json.dumps(disco), qos=1, retain=True)


def publish_availability(cli, state):
    # online ONLY when registered: otherwise HA would show "available" while
    # no ring can arrive.
    with state.lock:
        avail = "online" if state.registered else "offline"
    cli.publish(T_AVAIL, avail, qos=1, retain=True)


def _resolve_repondeur():
    """Player + recorder created at startup WITHOUT auto-play/auto-rec: they only
    run while connected with cc. An unconnected player is frozen (conference.c
    skips ports with no listener): it is kept connected for exactly the length of
    the file so it falls back to its start position; the silence at head and
    tail absorbs the few ms of drift per call."""
    global REP_OPTS, REP_PLAY_S
    try:
        import wave
        w = wave.open(REP_PLAY, "rb")
        try:
            fmt = (w.getframerate(), w.getnchannels(), w.getsampwidth())
            REP_PLAY_S = w.getnframes() / float(w.getframerate())
        finally:
            w.close()
    except Exception as e:  # noqa: BLE001
        log(f"answering machine: unreadable greeting ({e}) -> unavailable")
        return
    if fmt != (16000, 1, 2):
        log(f"answering machine: greeting format {fmt} != 16k/mono/s16 -> unavailable")
        return
    REP_OPTS = [f"--play-file {REP_PLAY}", f"--rec-file {REP_REC}"]
    log(f"answering machine: greeting {REP_PLAY_S:.2f} s")


def publish_repondeur_switch(cli):
    disco = {
        "name": "R\u00e9pondeur",
        "unique_id": "bticino_repondeur_local",
        "command_topic": T_REP_SET,
        "state_topic": T_REP_STATE,
        "payload_on": "ON",
        "payload_off": "OFF",
        "icon": "mdi:voicemail",
        "availability_topic": T_AVAIL,
        "payload_available": "online",
        "payload_not_available": "offline",
        "device": {
            "identifiers": ["bticino_easykit_25"],
            "name": "Portier BTicino EasyKit",
            "manufacturer": "BTicino/Legrand",
            "model": "Door Entry EASY KIT",
        },
    }
    cli.publish(T_REP_DISCO, json.dumps(disco), qos=1, retain=True)


def publish_call_rep(cli, ring_wall, dur):
    # No CANCEL arrives when we are the ones answering: the outcome is published here.
    payload = {
        "issue": "repondu_poste",
        "methode": "repondeur",
        "duree_s": round(dur, 1),
        "raison": "",
        "debut": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ring_wall)),
    }
    cli.publish(T_CALL, json.dumps(payload), qos=1, retain=True)
    log(f"call: repondu_poste (answering machine, {dur:.1f} s)")


def rep_worker(cli, q):
    """DEDICATED thread: cuts the message out of REP_REC, filters + Opus, publishes.
    Kept out of the stdout loop (ffmpeg would block the pjsua pipe there)."""
    import base64
    while True:
        item = q.get()
        if item is None:
            return
        start, end, ring_wall = item
        try:
            with open(REP_REC, "rb") as fh:
                fh.seek(start)
                raw = fh.read(max(0, end - start))
            raw = raw[: len(raw) - (len(raw) % 2)]
            secs = len(raw) / 32000.0
            if secs < 1.0:
                log(f"answering machine: message too short ({secs:.1f} s) -> dropped")
                continue
            r = subprocess.run(
                [FFMPEG, "-nostdin", "-v", "error",
                 "-f", "s16le", "-ar", "16000", "-ac", "1", "-i", "pipe:0",
                 "-af", REP_FILTER, "-ar", "48000", "-c:a", "libopus", "-b:a", "32k",
                 "-f", "ogg", "pipe:1"],
                input=raw, capture_output=True, timeout=60)
            if r.returncode != 0 or not r.stdout:
                log(f"answering machine: ffmpeg rc={r.returncode} {r.stderr[:200]!r}")
                continue
            payload = {
                "ogg_b64": base64.b64encode(r.stdout).decode("ascii"),
                "duree_s": round(secs, 1),
                "debut": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ring_wall)),
            }
            cli.publish(T_REP_MSG, json.dumps(payload), qos=1, retain=False)
            log(f"answering machine: message published ({secs:.1f} s, {len(r.stdout)} B ogg)")
        except Exception as e:  # noqa: BLE001 - one lost message does not kill the thread
            log(f"answering machine: message error: {e}")


def _sd_notify(msg):
    """Message to the service manager (WatchdogSec). Without NOTIFY_SOCKET: nothing."""
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return
    if addr[0] == "@":
        addr = chr(0) + addr[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sk:
            sk.sendto(msg.encode(), addr)
    except OSError:
        pass


def _fail_exit(cli, proc=None):
    if proc is not None:
        try:
            proc.kill()   # no orphan pjsua holding the AOR (bench mode especially)
        except Exception:
            pass
    try:
        cli.publish(T_AVAIL, "offline", qos=1, retain=True)
        time.sleep(0.5)   # let the PUBLISH go out before dying
        cli.loop_stop()
    except Exception:
        pass
    wipe()
    os._exit(1)


def send_open(state, target):
    """Injects a lock/light.setStatus MESSAGE into the stdin of the registered pjsua.
    Reproduces JsonRpcKotlin(Action.Lock|Stairlight, deviceAddr).toString()."""
    dev = OPEN_TARGETS.get(target)
    if not dev:
        log(f"unknown open command: {target!r}")
        return
    light = (target == "lumiere")
    # door lock = 10 s, gate/light = 3 s: anti-duplicate window.
    guard = 10.0 if target == "gache" else 3.0
    now = time.monotonic()
    with state.lock:
        last = state.last_cmd.get(target, 0.0)
        if now - last < guard:
            log(f"cmd {target} ignored (debounce {guard:.0f}s)")
            return
        state.last_cmd[target] = now
    payload = {
        "jsonrpc": "2.0",
        "id": str(int.from_bytes(os.urandom(4), "big")),
        "method": "light.setStatus" if light else "lock.setStatus",
        "params": [{"status": "on" if light else "open",
                    "receiver": {"plant": {"coal": {"id": dev}}}}],
    }
    nl = chr(10)
    line = "i" + nl + SIP_DIY + nl + json.dumps(payload, separators=(",", ":")) + nl
    with state.lock:
        proc = state.proc
    if proc is None or proc.poll() is not None:
        log("open command: pjsua not running -> ignored")
        return
    with state.stdin_lock:
        proc.stdin.write(line)
        proc.stdin.flush()
    log(f"MESSAGE {'light' if light else 'lock'}.setStatus sent (target={target})")


def publish_live_switch(cli):
    disco = {
        "name": "Voir le hall",
        "unique_id": "bticino_live_local",
        "command_topic": T_LIVE_SET,
        "state_topic": T_LIVE_STATE,
        "payload_on": "ON",
        "payload_off": "OFF",
        "icon": "mdi:cctv",
        "availability_topic": T_AVAIL,
        "payload_available": "online",
        "payload_not_available": "offline",
        "device": {
            "identifiers": ["bticino_easykit_25"],
            "name": "Portier BTicino EasyKit",
            "manufacturer": "BTicino/Legrand",
            "model": "Door Entry EASY KIT",
        },
    }
    cli.publish(T_LIVE_DISCO, json.dumps(disco), qos=1, retain=True)


def live_start(cli, state):
    """Starts the outgoing "see the entrance" call. Refused if a call (ring/answering
    machine) is already up, if live is already active, or if pjsua is missing. The call
    becomes current_call, so "h" (live_stop) hangs it up. LIVE_MAX_S is the last resort."""
    now = time.monotonic()
    with state.lock:
        proc = state.proc
        if now - state.live_last < 2.0:      # toggle debounce
            return
        if state.live_on or state.live_alive:
            log("live: already active -> ignored")
            return
        # A missed DISCONNECTED would leave a ghost id that refuses live forever.
        for cid in [c for c, t in state.calls.items() if now - t > CALL_STALE_S]:
            del state.calls[cid]
        if state.live_call is not None and state.live_call not in state.calls:
            state.live_call = None
        if state.calls or state.live_call is not None:
            log("live: a call is in progress -> refused (the doorbell must stay reachable)")
            cli.publish(T_LIVE_STATE, "OFF", qos=1, retain=True)
            return
        state.live_last = now
        state.live_on = True
        state.live_alive = True
    if proc is None or proc.poll() is not None:
        log("live: pjsua not running -> cancelled")
        with state.lock:
            state.live_on = state.live_alive = False
        cli.publish(T_LIVE_STATE, "OFF", qos=1, retain=True)
        return
    nl = chr(10)
    with state.stdin_lock:
        proc.stdin.write("m" + nl + SIP_DIY + nl)
        proc.stdin.flush()
    cli.publish(T_LIVE_STATE, "ON", qos=1, retain=True)
    log("live: outgoing 'view entrance' call started")
    # Hard cap: if nothing closes the live (no DISCONNECTED seen), hang up.
    cap = threading.Timer(LIVE_MAX_S, live_stop, args=(cli, state, "plafond"))
    cap.daemon = True
    with state.lock:
        state.live_cap = cap
    cap.start()


def live_stop(cli, state, why="demande"):
    """Hangs up the live IF and only IF the live is alive AND bound to its call id.
    "h" targets current_call: without a bound call id (CALLING never seen, or
    DISCONNECTED already passed) it could hang up a ring. An unbound live is cut by the
    door station. Lock order: state.lock THEN stdin_lock, as in repondeur(); the test
    and the send are atomic with respect to the DISCONNECTED read by the stdout loop."""
    with state.lock:
        proc = state.proc
        cap = state.live_cap
        state.live_cap = None
        state.live_on = False
    if cap is not None:
        cap.cancel()
    if proc is None or proc.poll() is not None:
        with state.lock:
            state.live_alive = False
        cli.publish(T_LIVE_STATE, "OFF", qos=1, retain=True)
        return
    with state.lock:
        alive = state.live_alive
        bound = state.live_call is not None
        state.live_alive = False
        if alive and bound:
            with state.stdin_lock:
                proc.stdin.write("h" + chr(10))
                proc.stdin.flush()
    if alive and bound:
        log(f"live: hung up ({why})")
    elif alive:
        log(f"live: call not bound -> no 'h' ({why})")
    cli.publish(T_LIVE_STATE, "OFF", qos=1, retain=True)


def jpeg_worker(cli, q):
    """DEDICATED thread: extracts 1 JPEG from the finalised AVI, then deletes it. NEVER
    in the stdout loop (ffmpeg would block the pjsua pipe -> SIP worker freezes).
    Each AVI is handled in isolation (try/except/finally): an error neither stops the
    thread nor leaves the AVI in the tmpfs."""
    while True:
        path = q.get()
        if path is None:
            return
        try:
            jpg = _extract_jpeg(path)
            if jpg:
                # T_PHOTO retained = the HA camera keeps the last image. The
                # NON-retained event triggers the automation (no replay when HA reboots).
                cli.publish(T_PHOTO, jpg, qos=1, retain=True)
                cli.publish(T_PHOTO_EVT, os.path.basename(path), qos=1, retain=False)
                log(f"photo published ({len(jpg)} B b64) from {os.path.basename(path)}")
            else:
                log(f"photo: no frame extracted from {os.path.basename(path)}")
        except Exception as e:  # noqa: BLE001 - a broken AVI does not kill the thread
            log(f"photo: extraction error {os.path.basename(path)}: {e}")
        finally:
            try:
                if DEBUG_KEEP:
                    import shutil
                    os.makedirs(DEBUG_DIR, exist_ok=True)
                    shutil.move(path, os.path.join(DEBUG_DIR, os.path.basename(path)))
                    # rotation: keep only the DEBUG_KEEP_N most recent
                    avis = sorted(
                        (os.path.join(DEBUG_DIR, f) for f in os.listdir(DEBUG_DIR)
                         if f.endswith(".avi")),
                        key=os.path.getmtime)
                    for old in avis[:-DEBUG_KEEP_N]:
                        try:
                            os.unlink(old)
                        except OSError:
                            pass
                    log("DEBUG_KEEP: AVI -> %s (keep %d)" % (DEBUG_DIR, DEBUG_KEEP_N))
                else:
                    os.unlink(path)
            except OSError as e:
                log(f"photo: AVI not moved/removed ({e}) -> unlink")
                try:
                    os.unlink(path)
                except OSError:
                    pass


def _extract_jpeg(path):
    """1 frame -> base64 JPEG. JPEG_SEEK window, falls back to the last frame if too
    short (call cancelled early). Returns base64 bytes or None. ffmpeg is bounded by a timeout."""
    import base64
    # MEASUREMENT: declared vs real frame rate. This is what settles "is 2.5 the end of the file?".
    try:
        pr = subprocess.run(
            [FFPROBE, "-v", "error", "-select_streams", "v:0",
             "-show_entries", "stream=nb_frames,avg_frame_rate,r_frame_rate,duration",
             "-of", "default=nw=1", path],
            capture_output=True, timeout=10, text=True)
        log("ffprobe %s: %s" % (os.path.basename(path),
                                " ".join(pr.stdout.split())))
    except Exception as e:  # noqa: BLE001
        log("ffprobe KO: %s" % e)
    # "index" branch = fixed frame N (robust to the declared fps); "sseof" fallback = last
    # frame if the call was cut before reaching frame N (very short AVI).
    for tag, args in (("index", ["-i", path, "-vf", "select='eq(n," + JPEG_FRAME + ")'"]),
                      ("sseof", ["-sseof", "-0.5", "-i", path])):
        try:
            r = subprocess.run(
                [FFMPEG, "-nostdin", "-v", "error", *args,
                 "-frames:v", "1", "-q:v", "2", "-f", "image2pipe", "-vcodec", "mjpeg", "-"],
                capture_output=True, timeout=15,
            )
            if r.returncode == 0 and r.stdout:
                log("photo: branch=%s (%d B jpeg)" % (tag, len(r.stdout)))
                return base64.b64encode(r.stdout)
        except subprocess.TimeoutExpired:
            log("photo: ffmpeg timeout (15 s)")
            return None
    return None


def main():
    atexit.register(wipe)  # a crash at startup still wipes the tmpfs
    _resolve_pjsua()       # picks the patched binary (capture) or the fallback (plain SIP)
    state = State()
    rep = {"diag": 0, "on": False, "seen": False, "ring": 0, "cancel": False, "busy": False,
           "cl": [], "rest": None, "play": None, "rec": None}
    _resolve_repondeur()
    mqtt_user, mqtt_pw = prepare_runtime()

    def rep_default_off(client):
        # nothing retained on T_REP_STATE = first start -> explicit OFF
        with state.lock:
            seen = rep["seen"]
        if not seen:
            client.publish(T_REP_STATE, "OFF", qos=1, retain=True)

    def on_connect(client, userdata, flags, rc, properties=None):
        # Replayed on EVERY (re)connection: otherwise the retained "offline" LWT keeps
        # the entity "unavailable" after any broker restart / NIC failover.
        log(f"MQTT (re)connected (rc={rc})")
        publish_discovery(client)
        publish_buttons(client)
        publish_call_sensor(client)
        if CAPTURE_ON:
            publish_camera(client)
        publish_availability(client, state)
        client.subscribe(T_CMD, qos=1)
        publish_repondeur_switch(client)
        client.subscribe(T_REP_SET, qos=1)
        client.subscribe(T_REP_STATE, qos=1)
        threading.Timer(5.0, rep_default_off, args=(client,)).start()
        # Live: never restored from a retained value. The REAL state is REPUBLISHED on every
        # (re)connection (STATE retained for HA, never read back here) without touching the invariants:
        # if the broker restarts DURING a live, forcing live_alive=False here
        # would stop live_stop from sending "h" (live never hung up) and would open the
        # answering-machine guard on current_call = the live. We only mirror the state.
        publish_live_switch(client)
        client.subscribe(T_LIVE_SET, qos=1)
        with state.lock:
            alive = state.live_alive
        client.publish(T_LIVE_STATE, "ON" if alive else "OFF", qos=1, retain=True)

    try:
        cli = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2, client_id="bticino-doorbell-53"
        )
    except (AttributeError, TypeError):  # paho < 2.0
        cli = mqtt.Client(client_id="bticino-doorbell-53")
    cli.username_pw_set(mqtt_user, mqtt_pw)
    cli.will_set(T_AVAIL, "offline", qos=1, retain=True)
    cli.reconnect_delay_set(min_delay=1, max_delay=30)
    def on_message(_c, _u, msg):
        val = msg.payload.decode(errors="replace").strip()
        if msg.topic == T_REP_STATE:
            if val in ("ON", "OFF"):
                with state.lock:
                    rep["on"] = (val == "ON")
                    rep["seen"] = True
            return
        if msg.topic == T_REP_SET:
            if msg.retain or val not in ("ON", "OFF"):
                log("answering machine: command ignored (retained or unknown value)")
                return
            with state.lock:
                rep["on"] = (val == "ON")
                rep["seen"] = True
            _c.publish(T_REP_STATE, val, qos=1, retain=True)
            log(f"answering machine: {val}")
            return
        if msg.topic == T_LIVE_SET:
            if msg.retain or val not in ("ON", "OFF"):
                log("live: command ignored (retained or unknown value)")
                return
            if val == "ON":
                live_start(_c, state)
            else:
                live_stop(_c, state, "demande")
            return
        if msg.topic != T_CMD:
            return
        if msg.retain:
            log("cmd ignored (retained -> replay guard)")
            return
        send_open(state, val)

    cli.on_connect = on_connect
    cli.on_message = on_message
    # connect_async: a broker that is unreachable at startup does not kill the SIP endpoint,
    # the paho thread retries on its own.
    cli.connect_async(MQTT_HOST, MQTT_PORT, keepalive=30)
    cli.loop_start()

    # bounded queue: with 4 AVIs pending, drop the newest (logged) rather than
    # block the stdout loop. Worker started only when capture is active.
    photo_q = queue.Queue(maxsize=4)
    if CAPTURE_ON:
        threading.Thread(target=jpeg_worker, args=(cli, photo_q), daemon=True).start()

    # BTCK_DEVADDR MUST be set before Popen: pjsua inherits os.environ (no env=).
    setup_devaddr_env()

    proc = subprocess.Popen(
        ["stdbuf", "-oL", "-eL", PJSUA, "--config-file", CFG_PATH],
        stdin=subprocess.PIPE,   # never closed => no EOF => pjsua stays alive
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        errors="replace",        # a non-UTF-8 byte does not kill the loop
    )
    with state.lock:
        state.proc = proc

    stopping = threading.Event()

    def cleanup(*_):
        if stopping.is_set():
            return
        stopping.set()
        try:
            cli.publish(T_AVAIL, "offline", qos=1, retain=True)
            cli.loop_stop()
            cli.disconnect()
        except Exception:
            pass
        try:
            proc.terminate()
        except Exception:
            pass
        wipe()
        os._exit(0)

    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)

    def watchdog():
        while not stopping.is_set():
            time.sleep(30)
            now = time.monotonic()
            with state.lock:
                ever, last, started, interval = (
                    state.ever, state.last_reg, state.started, state.reg_interval,
                )
            # Sent AFTER taking state.lock: a stuck lock = no more pings.
            _sd_notify("WATCHDOG=1")
            # interval = refresh granted by the door station (measured); +300 s margin.
            stale = interval + 300.0
            if not ever:
                if now - started > STARTUP_GRACE:
                    log("watchdog: never registered -> exit (systemd will restart)")
                    _fail_exit(cli, proc)
            elif last is not None and now - last > stale:
                log("watchdog: registration expired -> exit (systemd will restart)")
                _fail_exit(cli, proc)

    threading.Thread(target=watchdog, daemon=True).start()

    log(f"pjsua started (pid {proc.pid}), listening for INVITE")
    last_ring = 0.0
    ring_t = None        # monotonic of the current ring (None = no call)
    ring_wall = 0.0
    cancel = None        # [duration, reason, lines_read] while the CANCEL is being dumped
    last_start = None   # last BTCK-AVI-START seen (lock 3, anti-injection)
    pending_avi = None  # (path, timer): finalised AVI waiting for the DISCONNECTED
    rep_q = queue.Queue(maxsize=4)
    threading.Thread(target=rep_worker, args=(cli, rep_q), daemon=True).start()

    # Finalised AVI (DONE) waiting to be resolved by call id. Shared with the fallback
    # Timer: protected by its own lock, a path is resolved only once.
    avi_wait = {"lock": threading.Lock(), "done": set()}

    def resolve_avi(path, live):
        """Routes a finalised AVI: live (entrance) -> unlink; ring -> photo_q.
        Idempotent: the fallback Timer and the DISCONNECTED may both call it."""
        with avi_wait["lock"]:
            if path in avi_wait["done"]:
                return
            avi_wait["done"].add(path)
            if len(avi_wait["done"]) > 16:   # memory bound: set of handled paths
                avi_wait["done"] = set(list(avi_wait["done"])[-8:])
        if live:
            log(f"live: entrance AVI skipped (no photo) {os.path.basename(path)}")
            try:
                os.unlink(path)
            except OSError:
                pass
            return
        try:
            photo_q.put_nowait(path)
        except queue.Full:
            log("photo: queue full -> AVI dropped")
            try:
                os.unlink(path)
            except OSError:
                pass

    def resolve_avi_timeout(path):
        # Safety net: no DISCONNECTED seen within 2 s -> the PHOTO WINS (never the unlink).
        resolve_avi(path, live=False)

    def rep_send(cmd):
        with state.stdin_lock:
            proc.stdin.write(cmd + "\n")
            proc.stdin.flush()

    def rep_conf_list():
        with state.lock:
            rep["cl"] = []
        rep_send("cl")
        time.sleep(1.5)
        with state.lock:
            return list(rep["cl"])

    def rep_init():
        # conference slots of the player/recorder, read once pjsua is registered
        while not stopping.is_set():
            with state.lock:
                ever = state.ever
            if ever:
                break
            time.sleep(2)
        for _ in range(3):
            time.sleep(3)
            if rep_rest():
                log(f"answering machine: ready ({len(rep['rest'])} idle ports)")
                return
        log("answering machine: player/recorder not found -> disarmed")

    def rep_rest():
        # slots recorded while idle; a call port left open ends up there and
        # will be ignored on the next call
        ports = rep_conf_list()
        play = [p for p, t in ports if os.path.basename(REP_PLAY) in t]
        rec = [p for p, t in ports if os.path.basename(REP_REC) in t]
        if len(play) != 1 or len(rec) != 1:
            return False
        with state.lock:
            rep["play"], rep["rec"] = play[0], rec[0]
            rep["rest"] = [p for p, _ in ports]
        return True

    def repondeur(my, ring_wall, t0):
        time.sleep(REP_ANSWER_S)
        # same lock as the stdout loop's CANCEL: never a 200 on an
        # already cancelled call, one answering-machine call at a time
        with state.lock:
            # not live_alive is MANDATORY: during a live, the answering machine's "a"/"200"
            # would target current_call = the live, and its "h" would hang up the live.
            go = (rep["on"] and not rep["cancel"] and rep["ring"] == my
                  and not rep["busy"] and rep["play"] is not None
                  and not state.live_alive)
            if go:
                rep["busy"] = True
                rep["diag"] = 0
                rep_send("a")
                time.sleep(0.3)
                rep_send("200")
        if not go:
            return
        try:
            log("answering machine: answered (200)")
            time.sleep(2.0)
            ports = rep_conf_list()
            with state.lock:
                known = list(rep["rest"])
                play, rec = rep["play"], rep["rec"]
            new = [p for p, _ in ports if p not in known]
            if len(new) != 1:
                log(f"answering machine: call slot not found ({len(new)}) -> hang up")
                rep_send("h")
                return
            call = new[0]
            rep_send(f"cc {play} {call}")
            if REP_DIAG:
                log(f"diag: cc {play} {call} (known {known})")
                time.sleep(1.0)
                rep_send("cl")
                time.sleep(4.0)
                rep_send("dq")
                time.sleep(max(0.0, REP_PLAY_S - 5.0))
            else:
                time.sleep(REP_PLAY_S)
            rep_send(f"cd {play} {call}")
            start = os.path.getsize(REP_REC) + REP_SKIP_B
            rep_send(f"cc {call} {rec}")
            log("answering machine: greeting played -> recording")
            if REP_DIAG:
                time.sleep(1.0)
                rep_send("cl")
                time.sleep(9.0)
                rep_send("dq")
                time.sleep(max(0.0, REP_MSG_S - 10.0))
            else:
                time.sleep(REP_MSG_S)
            rep_send(f"cd {call} {rec}")
            publish_call_rep(cli, ring_wall, time.monotonic() - t0)
            rep_send("h")
            time.sleep(0.5)
            end = os.path.getsize(REP_REC)
            try:
                rep_q.put_nowait((start, end, ring_wall))
            except queue.Full:
                log("answering machine: queue full -> message lost")
        except Exception as e:  # noqa: BLE001
            log(f"answering machine: call error: {e}")
            try:
                rep_send("h")
            except Exception:
                pass
        finally:
            time.sleep(3.0)
            if not rep_rest():
                log("answering machine: idle port scan failed (previous scan kept)")
            with state.lock:
                rep["busy"] = False
            try:
                big = os.path.getsize(REP_REC) > REP_MAX_REC
            except OSError:
                big = False
            if big:
                log("answering machine: recording file full -> back to idle")
                time.sleep(30)   # let the worker publish the last message
                cleanup()

    if REP_OPTS:
        threading.Thread(target=rep_init, daemon=True).start()
    try:
        for line in proc.stdout:
            if REP_DIAG and rep['busy'] and rep['diag'] < REP_DIAG_MAX:
                dl = line.strip()
                if dl and not REP_DIAG_SKIP.search(dl):
                    rep['diag'] += 1
                    log("diag: " + dl[:220])
            mp = REP_PORT_RE.match(line.strip())
            if mp:
                with state.lock:
                    rep['cl'].append((int(mp.group(1)), line.strip()))
                continue
            # Call states are tracked at the TOP of the loop, with no "continue": a
            # "Call N ..." line can arrive DURING a CANCEL dump (cancel block below,
            # which does "continue"). Left to the elif chain, the DISCONNECTED of a
            # cancelled ring would be swallowed -> state.calls never empty -> live refused forever.
            # Here the line is always seen, then continues its normal path.
            mc = CALL_DISC_RE.search(line)
            if mc:
                cid = int(mc.group(1))
                with state.lock:
                    state.calls.pop(cid, None)
                    was_live = (state.live_call == cid)
                    if was_live:
                        state.live_call = None
                        state.live_alive = False
                        state.live_on = False
                if was_live:
                    cli.publish(T_LIVE_STATE, "OFF", qos=1, retain=True)
                    log("live: call ended (DISCONNECTED)")
                # Resolve the pending AVI if it belongs to the call that just ended.
                if pending_avi is not None:
                    pending_avi[1].cancel()   # the 2 s safety net is no longer needed
                    resolve_avi(pending_avi[0], live=was_live)
                    pending_avi = None
            else:
                ms = CALL_STATE_RE.search(line)
                if ms:
                    cid, st = int(ms.group(1)), ms.group(2)
                    with state.lock:
                        state.calls[cid] = time.monotonic()
                        # CALLING = start of an OUTGOING call (only the live makes one
                        # here). If a live is waiting for a call id, bind it.
                        if st == "CALLING" and state.live_alive and state.live_call is None:
                            state.live_call = cid
            if cancel is not None:
                m = REASON_RE.match(line.strip())
                if m:
                    cancel[1] = m.group(1).strip()
                cancel[2] += 1
                if END_MSG in line or cancel[2] > 40:
                    publish_call(cli, ring_wall, cancel[0], cancel[1])
                    cancel = None
                continue
            if ring_t is not None and CANCEL_RE.search(line):
                cancel = [time.monotonic() - ring_t, None, 0]
                with state.lock:
                    rep['cancel'] = True
                    if rep['busy']:
                        cancel = None   # call already taken: keep repondu_poste
                ring_t = None
                log("pjsua: " + line.rstrip()[:200])
                continue
            if RING_RE.search(line):
                with state.lock:
                    busy = rep['busy']
                if busy:
                    continue   # re-INVITE inside the answered call, not a ring
                now = time.monotonic()
                if now - last_ring > DEBOUNCE_S:
                    last_ring = now
                    ring_t = now
                    ring_wall = time.time()
                    cli.publish(T_STATE, "ring", qos=1)
                    log("RING detected -> published 'ring'")
                    with state.lock:
                        rep['ring'] += 1
                        rep['cancel'] = False
                        my = rep['ring']
                        ready = rep['play'] is not None
                    if ready:
                        threading.Thread(target=repondeur, args=(my, ring_wall, now),
                                         daemon=True).start()
            elif REG_OK_RE.search(line):
                now = time.monotonic()
                # pjsua prints "will re-register in N seconds" => exact interval.
                # Only N is logged (the raw line carries the AOR, hence the CN).
                m = REG_IN_RE.search(line)
                with state.lock:
                    if m:
                        state.reg_interval = int(m.group(1))
                    elif state.last_reg is not None:
                        obs = now - state.last_reg   # fallback: measured between 2 refreshes
                        if 30 < obs < 7200:
                            state.reg_interval = obs
                    state.last_reg = now
                    state.registered = True
                    state.ever = True
                    shown = state.reg_interval
                publish_availability(cli, state)
                log(f"REGISTER 200 (registered, re-register ~{int(shown)}s)")
            elif REG_FAIL_RE.search(line):
                with state.lock:
                    state.registered = False
                publish_availability(cli, state)
                log("REGISTER failed -> availability offline")
            elif CAPTURE_ON and BTCK_AVI_RE.match(line):
                m = BTCK_AVI_RE.match(line)
                kind, path = m.group(1), m.group(2)
                # lock 2: path INSIDE RUN_DIR + name rx_<epoch>_<seq>.avi
                d, b = os.path.dirname(path), os.path.basename(path)
                if d != RUN_DIR or not BTCK_NAME_RE.match(b):
                    log(f"BTCK ignored (path outside RUN_DIR): {b}")
                elif kind == "START":
                    last_start = path   # lock 3: remember the last START
                elif kind == "DONE":
                    # lock 3: a DONE is handled only if it follows its START.
                    # The AVI is NOT sent right away: btck_avi_rotate() prints DONE
                    # BEFORE the "Call N is DISCONNECTED" that says WHICH call produced it.
                    # The AVI is put on hold and resolved on that DISCONNECTED:
                    #   N == live_call -> live (entrance), unlink (no false photo);
                    #   otherwise      -> ring, photo_q.
                    # Safety net (no-loss fix): if the DISCONNECTED
                    # is not seen within 2 s, the PHOTO WINS (photo_q), never the unlink.
                    if path == last_start:
                        if pending_avi is not None:
                            # successive DONEs with no DISCONNECTED in between: resolve
                            # the previous one as a photo (safe default) before queueing the new one.
                            resolve_avi(pending_avi[0], live=False)
                        timer = threading.Timer(
                            2.0, resolve_avi_timeout, args=(path,))
                        timer.daemon = True
                        pending_avi = (path, timer)
                        timer.start()
                    else:
                        # lock 2 already passed => the file is ours: delete it
                        # anyway (otherwise it leaks into the tmpfs if DONE/START cross).
                        log(f"BTCK DONE without matching START, unlink: {b}")
                        try:
                            os.unlink(path)
                        except OSError:
                            pass
            elif HDR_RE.search(line):
                log("pjsua: " + line.rstrip()[:200])
    finally:
        try:
            proc.terminate()
            proc.wait(5)
        except Exception:
            pass

    log("pjsua exited -> exit (systemd will restart)")
    cleanup()


if __name__ == "__main__":
    main()

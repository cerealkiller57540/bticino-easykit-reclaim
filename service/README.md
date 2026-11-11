# The always-on client (`service/`)

This is the client that runs in production in the author's house, copied byte for byte:
`bticino_doorbell.py` and `bticino_live.py` are the deployed files. Only the per-install values
were moved out of the code into a JSON file, so you can run them with your own values.

It is a **reference implementation, not a package**. It fits one house and one door station. Read
it, adapt it, and expect to change paths and names. You can only use it once you have done
§3–§6 of the [main README](../README.md): extracted your TLS identity, built mbedTLS 3.6.x and
pjproject, and seen your own `REGISTER` get a `200 OK`.

## What it does

| Feature | README section | MQTT |
| --- | --- | --- |
| Ring detection | §9 | `bticino/sonnette/state` → `ring` |
| Visitor photo on ring | §9 | `bticino/portier/photo` (base64 JPEG, retained), `bticino/portier/photo/event` (file name, not retained) |
| Outcome of each call | §9 | `bticino/portier/appel` (JSON, retained) |
| Local door/gate/light opening | §8 | `bticino/portier/cmd`, payload = a key of `open_targets` (**never retained**) |
| Answering machine | §11 | `bticino/repondeur/set` (`ON`/`OFF`), `.../state` (retained), `.../message` (JSON `{"ogg_b64", "duree_s", "debut"}`) |
| Live view of the entrance | §10 | `bticino/live/set` (`ON`/`OFF`), `.../state` |
| Availability | — | `bticino/sonnette/availability` (`online` only once `REGISTER` has succeeded) |

All entities are created by MQTT Discovery under `homeassistant/...`. The open buttons come from
the keys of `open_targets`, one button per key.

Topic names, the `open_targets` keys (`gache` = door lock, `portail` = gate, `lumiere` = light),
the JSON field names and the log messages are in French. The code and comments are in English.
These names were left as they are on purpose, so that the published files stay identical to the
deployed ones. Rename them if you like.

## Files

```text
service/
  bticino_doorbell.py      the SIP endpoint: pjsua wrapper + MQTT (Python 3, paho-mqtt)
  bticino_live.py          tails the growing call AVI and pushes it to go2rtc over RTSP
  site.example.json        the per-install values (copy to /etc/bticino/site.json)
  systemd/
    bticino-doorbell.service
    bticino-doorbell.service.d/{site,live,watchdog}.conf
    bticino-live.service
```

`<user>` in the unit files is the account the service runs as.

## Requirements

- **The patched pjsua** from [`../pjsua-patch/`](../pjsua-patch/), built against mbedTLS 3.6.x
  with video and ffmpeg enabled. It adds one AVI per call and, on the outgoing live call, the door
  station address plus a `sendrecv` video offer.
- `python3`, `python3-paho-mqtt` (1.x or 2.x), `ffmpeg` and `ffprobe`,
  `stdbuf` (coreutils).
- An MQTT broker with an **ACL** on `bticino/portier/cmd` (see §9: that topic drives a relay).
- For the live view only: [go2rtc](https://github.com/AlexxIT/go2rtc) on the same host, with an empty
  stream named `portier` that accepts RTSP publishing on `127.0.0.1:8554`. In Home Assistant, a
  `generic` camera points at that stream.
- systemd ≥ 250 with `systemd-creds` and a TPM2 if you want the sealed credentials below. The
  bench mode reads the secrets through [`rbw`](https://github.com/doy/rbw) instead.

## Setup

### 1. Lay out the files

The code expects this layout under the service user's home (change the constants if you want
another one):

```text
~/bticino-proof/
  bticino_doorbell.py
  bticino_live.py
  pjsua-btck-avi-sendrecv            the patched binary (a stable copy, outside the build tree)
  pjproject/pjsip-apps/bin/pjsua-x86_64-pc-linux-gnu   fallback: stock pjsua, ring only
  repondeur/annonce_prod.wav         the answering-machine greeting
  avi_debug/                         only used with BTCK_DEBUG_KEEP=1
```

### 2. Pin the binary checksum — required

At startup the client hashes the patched binary and compares it with `PJSUA_SHA16`. If they differ,
the client **quietly falls back** to the stock pjsua. Rings are still detected, but there is no
photo, no answering machine and no live view, and the only sign is one log line. The value in the
file is the hash of the author's build. Yours will be different, so set it:

```bash
cp <pjproject>/pjsip-apps/bin/pjsua-x86_64-pc-linux-gnu ~/bticino-proof/pjsua-btck-avi-sendrecv
sha256sum ~/bticino-proof/pjsua-btck-avi-sendrecv | cut -c1-16
# put that value in PJSUA_SHA16 in bticino_doorbell.py
```

The check is there so that a rebuild or a relink can't quietly swap in a different binary. Keep it.

### 3. The site config

Copy `site.example.json` to `/etc/bticino/site.json` (`root:root`, mode `600`) and fill it in:

- `sip_user`: your certificate CN, which is also the SIP user (§6);
- `sip_domain`: the SIP domain you register against;
- `sip_proxy`: `<doorstation-ip>:<port>` of the door station's SIP-TLS listener;
- `open_targets`: the relay deviceAddrs (§8), one per button;
- `mqtt_host` and `mqtt_port`: your broker;
- `vault_sip` and `vault_mqtt`: `rbw` item names, used only in bench mode (see below).

systemd hands it to the service as the `site` credential (`site.conf`). On the bench, point
`BTCK_SITE` at the file.

The door station's own deviceAddr (needed only for the live view) goes in a separate file,
`/etc/bticino/devaddr_platine` (one UUID, mode `600`), handed over by `live.conf`. Without it,
everything except the live view still works.

### 4. Seal the secrets

Five secrets are needed: the client key, the client certificate (all PEM blocks), the SIP
password, the MQTT username and the MQTT password. Seal each one to the TPM, one file per secret:

```bash
sudo install -d -m 700 /etc/bticino/creds
# example for the SIP password; do the same for sip.key, sip.crt, mqtt.user, mqtt.pw
sudo systemd-creds encrypt --with-key=tpm2 --name=sip.pw /path/to/sip.pw /etc/bticino/creds/sip.pw.cred
sudo shred -u /path/to/sip.pw
```

The `--name` must match the credential name in the unit. systemd decrypts the secrets into a tmpfs
before the service starts, so no password manager is needed at boot.

**Bench mode** (started by hand, no `CREDENTIALS_DIRECTORY`): the client reads the same secrets
from `rbw`:

- the `vault_sip` item holds the SIP password, and its notes hold the EC private key and the
  certificate PEM blocks;
- the `vault_mqtt` item holds the MQTT username and password.

### 5. Install the units

```bash
sudo cp systemd/bticino-doorbell.service systemd/bticino-live.service /etc/systemd/system/
sudo cp -r systemd/bticino-doorbell.service.d /etc/systemd/system/
# replace <user> in the copies, then:
sudo systemctl daemon-reload
sudo systemctl enable --now bticino-doorbell.service bticino-live.service
journalctl -u bticino-doorbell -f    # expect a 200 REGISTER, then "pjsua patche OK"
```

### 6. The greeting

`repondeur/annonce_prod.wav` must be **16 kHz, mono, 16-bit PCM**. Any other format is refused, and
the answering machine stays unavailable. Put a little silence at the start and at the end. The
player is rewound by keeping it connected for exactly the file's length, and the silence absorbs
the few milliseconds of drift per call.

## What stays on the Home Assistant side

These are not published here, because they are specific to the author's house. You write them yourself:

- an automation on `bticino/portier/photo/event` (for example, send the photo as a notification);
- a consumer for `bticino/repondeur/message`, which decodes `ogg_b64` and sends the Ogg/Opus clip
  wherever you want it;
- whatever switches the answering machine on when nobody is home (see the presence trap in §11);
- the go2rtc stream and the `generic` camera for the live view, plus a card that is visible only
  while the live switch is on (§10).

## Environment variables

| Variable | Used by | Purpose |
| --- | --- | --- |
| `CREDENTIALS_DIRECTORY` | doorbell | set by systemd; selects service mode |
| `RUNTIME_DIRECTORY` | doorbell | set by systemd (`/run/bticino`); `/dev/shm/bticino` on the bench |
| `BTCK_SITE` | doorbell | path to `site.json` in bench mode |
| `BTCK_DEBUG_KEEP=1` | doorbell | keep each ring's AVI in `BTCK_DEBUG_DIR` (timing measurements; off by default) |
| `BTCK_DEBUG_DIR`, `BTCK_FFPROBE` | doorbell | where those AVIs go, which ffprobe to use |
| `BTCK_LIVE_DIR` | live | where the call AVIs appear (default `/run/bticino`) |
| `BTCK_LIVE_URL` | live | RTSP publish URL (default `rtsp://127.0.0.1:8554/portier`) |

`BTCK_DEVADDR` is set by the client itself from the `devaddr` credential and read by the patched
pjsua. Never put it on a command line.

## Things to know

- **`REP_DIAG = True` is a temporary diagnostic.** During an answering-machine call it copies the
  pjsua output to the log, without the SIP and SDP lines, which carry the SRTP keys. It was left on
  to investigate one silent answer. Set it to `False` once your answering machine behaves.
- **Logs are scrubbed.** `log()` masks every `inline:` SRTP key and every UUID before it writes to
  journald. Keep that if you add log lines: the live call's INVITE carries the door station's
  deviceAddr.
- **One registration per account** (§8). Don't run the bench client while the service is running:
  the second `REGISTER` evicts the first, and nothing is listening for the doorbell anymore.
- **Timings are measured on one device.** Examples: 29.7 s for an unanswered ring, about 18 s for
  the CANCEL when someone answers on the indoor unit, about 63 s before the door hangs up an
  outgoing call, and frame 10 for the photo. Measure yours before you trust them.

## License

MIT, like the rest of the repo (see [`../LICENSE`](../LICENSE)). Note that the pjsua patch in
`../pjsua-patch/` is under PJSIP's license instead.

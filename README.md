# Reclaiming a BTicino / Legrand EasyKit door station on the local network

> **Status: the hard parts are proven in production.** The reverse-engineering chain below works
> end to end: the TLS client identity is recovered from the vendor app, the mutual-TLS handshake to
> the door station succeeds, and a SIP `REGISTER` is accepted (`200 OK`) — all on the LAN, with no
> cloud. On top of that, a background client **catches the incoming call and grabs a photo of the
> visitor on ring** ([§9](#9-catching-the-ring-and-grabbing-a-photo)), and the gate/lock is
> **opened locally** over the same SIP channel ([§8](#8-opening-the-door-locally)) — both running
> and proven, both cloud-free. What is left is polish (full live media, richer event history,
> night-time tuning); those parts are in [§10](#10-work-in-progress--where-this-is-going).
>
> **What this does.** This project *reads* the door station — it knows when someone rings and grabs
> a photo of the visitor on ring — and it *drives* it: the gate/lock-release command travels over
> the **same local SIP channel**, as a small SIP `MESSAGE`, with **no cloud** (see
> [§8](#8-opening-the-door-locally)). Earlier write-ups (this one included, in an earlier revision)
> claimed opening had to go through the vendor cloud over HTTPS. Reading the decompiled app
> ([§2](#2-decompiling-the-app--the-backbone)) showed that is false: it is local, and it is proven.

## Why bother — planned obsolescence

The hardware is a competent little SIP/TLS intercom. It speaks a standard protocol (SIP over
TLS), it has a camera, it can register internal handsets. But the vendor gates almost everything
behind their app and their cloud, ships firmware that stops gaining features, and gives the owner
no local, documented way in. The device is capable of far more than the editor lets you do with
it, and the editor has no intention of changing that.

This is a small push back against that: the box is *yours*, it sits on *your* network, and the
protocol it speaks is open. The only thing in the way is that the vendor encrypted the keys to
their own device and handed you an app instead of a manual. This write-up is how you get the keys
back and talk to your own hardware directly.

**Nothing here is a vendor secret in the cryptographic sense.** The method recovers *your own
device's* identity, which already lives on *your own* phone — the app just keeps it encrypted at
rest. Everything is done on hardware you own, on your own LAN.

## ⚠️ Read this before anything else — scope, legality, redaction

- **Do this only on a device you own, on your own network.** Pulling a TLS client identity out of
  an app and using it to authenticate is fine when the identity is *yours* and the device is
  *yours*. It is not fine on someone else's building.
- **No real identifiers are published here.** Everything device-specific is a placeholder:
  `<doorstation-ip>`, `<sip-user>`, `<sip-domain>`, `<client-cn>`, `sip:<ext>`. The actual TLS
  private key, client certificate and SIP password are **not** in this repo and never will be —
  they live in a password manager and are read on demand. See [§7](#7-handling-the-identity-safely).
- **The whole chain is device-specific.** Your cipher-suite list, your SIP domain, your account
  format will differ. The *method* transfers; the values do not.

---

## 0. Prerequisites — before you start

This is a serious afternoon (or two). It is "hard but doable", and the thing that makes it feel
scarier than it is, is that it touches four worlds at once: Android reverse-engineering, a C build
toolchain, TLS internals, and SIP. You do **not** need to be an expert in all four — but you need
each tool present and working before you begin, or you will blame step 5 for a step-0 problem.

### The reference environment: WSL2 (Ubuntu)

The write-up assumes a **Windows 11 host with WSL2 running Ubuntu 22.04/24.04**. That is the path
this project actually used, and it is the most reproducible one for a Windows developer:

- The **Linux side (WSL)** builds and runs everything C/Java: jadx, mbedTLS, PJSIP, `pjsua`, the
  background service. Building mbedTLS/PJSIP on Windows natively (MSYS2/mingw) is possible but a
  minefield — don't, for a first run.
- The **Windows side** runs the Android emulator and talks to it: the Android SDK, `adb` and Frida
  all run fine on Windows, and the emulator is far happier on the Windows host than inside WSL. So:
  **emulator + `adb` + Frida on Windows, build/run everything else on WSL.** The one file you carry
  across (`\\wsl$\…` or a shared folder) is the recovered identity.

> If you already run a native Linux box or VM, use it — build there and run the emulator there too;
> skip the WSL notes. The only reason to split across Windows and WSL is that the emulator and USB
> stack behave better on the Windows host.

### What you need installed

|Tool|Version (tested)|Where|Install|
|---|---|---|---|
|**jadx**|**1.5.6**|WSL|download the release zip, unzip, needs a JDK|
|**JDK**|**17** (for jadx)|WSL|`sudo apt install openjdk-17-jdk`|
|**build toolchain**|gcc/make/cmake/git/python3|WSL|`sudo apt install build-essential cmake git python3 pkg-config`|
|**mbedTLS**|**3.6.x** (tested 3.6.7) — **not 4.x**|WSL, from source|see §4/§5; the script does it|
|**PJSIP (pjproject)**|**2.17**, against mbedTLS 3.6.x|WSL, from source|see §6; the script does it|
|**ffmpeg + ffprobe**|any recent|WSL|`sudo apt install ffmpeg`|
|**Android SDK + emulator**|cmdline-tools + a Google-APIs AVD|**Windows** (or host)|Android Studio, or `sdkmanager`/`avdmanager`|
|**Android Platform-Tools**|any recent (`adb`)|**Windows**|bundled with the SDK, or Google's standalone zip|
|**Frida**|16.x (`frida-tools`)|**Windows**|`pip install frida-tools`|
|**An MQTT broker**|e.g. Mosquitto|where your home-automation lives|for §8/§9 wiring|

### The Android side — use an emulator, not a rooted phone

The identity extraction (§3) needs an Android where Frida can spawn and instrument the app. A
**rooted physical phone works but is rare and risky nowadays** — so the recommended path is a
throwaway **Android Studio / SDK emulator (AVD)**, which gives you a clean, disposable, root-capable
Android for free:

- Create an AVD with a **"Google APIs" system image (not "Google Play")** — the Google-APIs images
  let you run `adb root` and drop a `frida-server`, which the locked Play images don't.
- Install the companion app's **APK** into the AVD (`adb install app.apk`). Pull the APK from a
  phone that has it (`adb shell pm path <pkg>` → `adb pull`), or get it from the vendor's store
  listing.
- **Networking caveat**: the pairing/provisioning flow may want to reach the real door station on
  your LAN. The emulator sits behind a NAT, so make sure it can route to `<doorstation-ip>` (on
  Windows the default emulator network usually can; if not, bridge it or run the AVD on the host
  network). This is the one place the emulator path needs a glance, not the rooted-phone drama.

Everything **after** the extraction is pure Linux — no phone or emulator involved.

Also needed: **network reach** to the door station on the LAN (its IP and the SIP-TLS port).

### The skills it assumes

Honest about the level: you should be comfortable *running* commands in a Linux shell, building a
C project from source (and reading a build error), and poking at an Android app with `adb`. You do
**not** need to read obfuscated Java fluently, write TLS code, or know SIP — the hard findings are
already distilled into this document; you are reproducing them, not rediscovering them.

### Scripts to take the pain out

The toolchain build (mbedTLS + PJSIP) is the part that looks scariest and is actually the most
mechanical — so it is scripted end to end. The repo's [`scripts/`](scripts/) directory has, run in
order:

|Script|What it does|Automatable?|
|---|---|---|
|`00-setup-toolchain.sh`|apt deps, build **mbedTLS 3.6.7**, build **PJSIP 2.17** against it|**Fully** — this is the wall, and it's a one-shot|
|`10-decompile.sh <apk>`|run jadx with the right flags into `out/`|Fully (you supply the APK)|
|`20-dump-identity.js` + `20-extract.sh <pkg>`|Frida hook to capture the identity|**Interactive** — you clear the app and walk the pairing flow by hand (§3)|
|`30-prove-handshake.sh`|`ssl_client2` against the door, reads identity from your vault|Fully (once you hold the identity)|
|`40-register.sh`|`pjsua` REGISTER, confirms the `200 OK`|Fully|

There is deliberately **no single "do everything" button**: the identity extraction (§3) is
inherently interactive (a running emulator, a pairing flow you click through), so anyone promising a
one-click AIO for *that* step is hand-waving. Everything on either side of it is scripted.

---

## The short version

A BTicino/Legrand EasyKit door station is, under the vendor skin, a SIP endpoint protected by
**mutual TLS**. To talk to it locally you need to present a client certificate it trusts — and that
certificate, its private key, and the SIP account parameters are all sitting inside the companion
Android app, encrypted at rest.

The chain is:

1. **Decompile the app and read how it actually talks to the door** — this is the backbone of
   the whole effort. A static read of the APK tells you the SIP address format, the media
   directions, the encryption it expects, and — later — how ringing and door-opening really work.
   Everything else is guided by what you find here — [§2](#2-decompiling-the-app--the-backbone).
2. **Pull the TLS identity out of the app.** The key + cert are encrypted at rest; a small
   runtime hook on the decrypt primitive captures the plaintext the app itself produces — one
   targeted brick, not the whole job — [§3](#3-pulling-the-tls-identity-out-of-the-app).
3. **Discover the door's TLS constraints** — it only accepts a handful of *static-ECDH* cipher
   suites, which modern OpenSSL has removed — so you must build the client on **mbedTLS 3.6.x**
   — [§4](#4-the-tls-wall-static-ecdh-and-why-openssl-wont-do).
4. **Prove the handshake** with a raw TLS client — [§5](#5-proving-the-handshake).
5. **Register over SIP-TLS** with PJSIP, working around a certificate-name mismatch — [§6](#6-registering-over-sip-tls).

After that you have a registered local endpoint. From there, the static read in §2 is what turns
registration into real features: catching the ring and grabbing a photo on ring
([§9](#9-catching-the-ring-and-grabbing-a-photo)), and even driving the door locally
([§8](#8-opening-the-door-locally)) — both proven, both cloud-free.

---

## 1. What you're up against

The door station (`<doorstation-ip>` on your LAN) listens for SIP over TLS. Two things make a
naive connection fail:

- **Mutual TLS.** The server doesn't just present a cert, it *demands* a client cert signed by a
  CA it trusts. No client cert → the handshake dies. The only place that client identity exists,
  outside the device, is the vendor app.
- **A deliberately narrow TLS profile.** The server negotiates only a few old cipher suites built
  on *static* ECDH (fixed-key, `prime256v1`). That matters enormously for tooling — see §4.

So before any SIP packet is sent, you have to (a) extract the identity and (b) have a TLS stack
that can even complete the handshake.

---

## 2. Decompiling the app — the backbone

Almost nothing in this project was guessed. Every decision — which SIP address to dial, whether to
offer video, which encryption the door demands, how the doorbell actually reaches you, how the app
opens the gate — came out of **reading the decompiled app**. If you do one thing before touching
the network, do this.

The companion app is an Android APK wrapping the **Linphone** SIP stack. Decompile it to readable
Java with **jadx**:

```bash
# jadx 1.5.x, with a JDK 17 on PATH
jadx --no-res --show-bad-code -j2 -d out/ com.<vendor>.<app>.apk
```

You get a few thousand `.java` files. The class names are obfuscated (`a.java`, `b.java`,
`C0616f.java`…), but the Linphone SDK calls are not — and those calls are the map. What reading it
tells you, and why each point matters downstream:

- **The real SIP address is assembled at runtime.** The only literal in the DEX is the user part
  (here, `diy`); the domain is appended from the *default proxy config* — i.e. the door's own
  cloud FQDN — **not** the LAN IP. Every early attempt that dialled the device by IP was dialling
  the wrong address. You only learn the right form by reading the call-building code.
- **The call that shows the hallway asks for video `RecvOnly`, audio inactive**, and carries the
  target's device address as a *custom SDP attribute* — not a SIP header. That single fact decides
  whether a command-line client can reproduce the outgoing "see the hall" call at all (it can't —
  it can't inject an arbitrary SDP attribute), and it is also what tells you the **incoming** ring
  carries video you *can* grab without any such attribute (see [§9](#9-catching-the-ring-and-grabbing-a-photo)).
- **Door-opening is a local SIP `MESSAGE`, not a cloud call.** The "slide to open" action builds a
  small JSON-RPC body and sends it over the *same* local SIP channel. This is the single most
  important correction to the folklore around these devices — see [§8](#8-opening-the-door-locally).
- **The factory config ships in `res/raw`.** The embedded `linphonerc` reveals the SIP transport,
  whether the server certificate's name is verified, and the media-encryption policy. Read it
  before you fight the handshake — it saves you from blaming the wrong layer.

Keep the decompiled tree around. Throughout the rest of this write-up, the answer to "but how do
you *know* that?" is almost always "it's in the decompiled call path."

---

## 3. Pulling the TLS identity out of the app

With the call path understood, you still need the client identity the door's mutual-TLS demands:
an **EC P-256 private key**, the matching **X.509 client certificate**, the **CA chain**, and the
**SIP account parameters** (username, domain/realm, password, registrar). The cert and key are
stored **encrypted at rest** — the app wraps them with a key held in the Android Keystore — while
the public cert and CA chain sit in the clear.

You do not need to reverse the key-derivation or the storage format. The app decrypts its own
identity in memory when it connects, so the clean capture is a small runtime hook on the decrypt
primitive — one targeted brick on top of the static read, not a second reverse-engineering effort.

On Android this funnels through `javax.crypto.Cipher`. Hook `doFinal` **and only act when the
cipher is in DECRYPT mode** — otherwise you also dump everything the app *encrypts*, which is noise:

```js
// frida -U -f com.<vendor>.<app> -l dump_identity.js   (spawn, not attach — see below)
Java.perform(function () {
  const Cipher = Java.use('javax.crypto.Cipher');
  const DECRYPT_MODE = 2;

  // Remember the mode each Cipher instance was initialised with.
  Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
    this._mode = mode;
    return this.init(mode, key);
  };
  // (hook the other init overloads the same way — several exist)

  function dump(tag, out) {
    if (this._mode !== DECRYPT_MODE || out === null) return;
    const b = Java.array('byte', out);
    console.log('\n--- doFinal DECRYPT (' + tag + ', ' + b.length + ' bytes) ---');
    // Print as hex AND as text; identity blobs are often PEM/ASN.1 or JSON.
    console.log(hexdump(b, { length: Math.min(b.length, 4096), ansi: false }));
  }

  Cipher.doFinal.overload('[B').implementation = function (input) {
    const out = this.doFinal(input);
    dump.call(this, 'doFinal([B)', out);
    return out;
  };
  Cipher.doFinal.overload().implementation = function () {
    const out = this.doFinal();
    dump.call(this, 'doFinal()', out);
    return out;
  };
});
```

> **Why hook the decrypt and not read the file?** The blob on disk is ciphertext; the key to
> decrypt it lives in the Keystore and is applied at runtime. Hooking the decrypt output skips all
> of that — you get the finished plaintext the app was about to use, regardless of how it was
> stored or keyed.

**The catch — force a fresh decrypt.** The app only decrypts the identity when it has a reason to:
typically during **provisioning/pairing**, or the first connection after a fresh install. An app
that already has everything cached and idle may never fire `doFinal` with the material you want —
and an identity written under an *old* Keystore key can even throw `BadPaddingException`. The
reliable way is to make the app **provision again**: clear its data (or reinstall), spawn it
*under* the hook (`frida -f …`, spawn-gating — hooked **before** the first crypto call, not
attached after), then walk the pairing/login flow. The identity is decrypted as part of coming
online, written fresh under the current Keystore key, right in front of your hook.

---

## 4. The TLS wall: static-ECDH, and why OpenSSL won't do

With the identity in hand, the next wall is the handshake itself. The door station accepts only a
small set of cipher suites, and they are all built on **static ECDH** over `prime256v1` — the
fixed-key elliptic-curve key exchange, e.g. the `ECDH-ECDSA-*` / `ECDH-RSA-*` families (note:
`ECDH-*`, *not* the ephemeral `ECDHE-*`).

That single fact decides your whole toolchain:

- **OpenSSL 3.x cannot do it.** Static-ECDH suites were removed from OpenSSL years ago. Any client
  built on a current OpenSSL — which is almost everything, including stock `openssl s_client`,
  current cURL, most language TLS bindings — will offer only ephemeral suites, the server will
  find no common suite, and the handshake fails at "no shared cipher". This is the single biggest
  time-sink; it looks like an auth problem but it's a *cipher* problem.
- **You need mbedTLS, and specifically the 3.6.x LTS line.** mbedTLS still implements static-ECDH
  suites. **Use 3.6.x, not 4.x** — the 4.x line dropped them too. Build mbedTLS 3.6.x yourself.

So the client side of this project is built on **mbedTLS 3.6.x**. Everything downstream (the SIP
stack) has to be built against *that* mbedTLS, not the system OpenSSL.

---

## 5. Proving the handshake

Before dragging a whole SIP stack into it, prove the TLS layer alone with mbedTLS's own sample
client, `ssl_client2`, built from the 3.6.x tree.

```bash
# Build mbedTLS 3.6.x with the sample programs, then:
./programs/ssl/ssl_client2 \
    server_addr=<doorstation-ip> server_port=<sip-tls-port> \
    key_file=client.key crt_file=client.crt \
    debug_level=2
```

Reading the debug output:

- You want to reach **"Protocol is TLSvX.X / Ciphersuite is TLS-ECDH-…"** — that line is the proof
  that the static-ECDH negotiation succeeded and your client cert was accepted.
- If instead it stops at a handshake failure early on, you're almost certainly still on an
  OpenSSL-based build (see §4) or the cert/key pair isn't the one the server expects.

Once `ssl_client2` completes the handshake, the hard cryptographic part is done: you have proven a
mutually-authenticated TLS session to the door station, locally.

---

## 6. Registering over SIP-TLS

Now put SIP on top. PJSIP (pjproject) is the natural choice, **built against the mbedTLS 3.6.x
from §4** (configure pjproject to use mbedTLS, not OpenSSL — otherwise you're back behind the
cipher wall).

A minimal `pjsua` account, with placeholders:

```ini
--id             sip:<sip-user>@<sip-domain>
--registrar      sip:<doorstation-ip>:<sip-tls-port>;transport=tls
--realm          *
--username       <sip-user>
--password       <sip-password-from-identity>     # read from your vault, never hard-code
--tls-cert-file  client.crt
--tls-privkey-file client.key
```

### The certificate-name mismatch, and the workaround

The server's certificate doesn't present a name that matches `<doorstation-ip>` — the CN is a
device-specific identifier (`<client-cn>`), not the IP you're connecting to. A strict TLS client
*verifies* the server name and aborts on the mismatch.

The pragmatic workaround on a trusted LAN is **not to pass a CA file for server verification**
(`--tls-ca-file` omitted). Without a CA to verify against, PJSIP completes the handshake instead of
rejecting the name mismatch. On your own network, against your own device, that's an acceptable
trade; it is *not* something to carry over to anything facing the internet.

With that in place, the registrar accepts the account:

```text
registration success, status=200 (OK)
```

That `200 OK` is the milestone: a **local, cloud-free, mutually-authenticated SIP registration** to
a door station the vendor intended to be reachable only through their app.

---

## 7. Handling the identity safely

The recovered material — EC private key, client certificate, SIP password — is the keys to your
door station's local interface. Treat it like any other private key:

- **It is not in this repo** and the `.gitignore` here actively blocks `*.key`, `*.pem`, `*.cfg`,
  captures and dumps from being committed.
- Keep it in a password manager / secrets store, and have the client read it at run time rather
  than writing it into a config file in the clear.
- Never paste the private key or the SIP password into an issue, a log, or a chat. If you need to
  share *how*, share this method — not your values.

---

## 8. Opening the door locally

The folklore around these devices — and an earlier revision of this very document — says the
gate/lock command has to go through the vendor cloud. Reading the decompiled "slide to open" code
path (§2) shows that is wrong. **The open command is a SIP `MESSAGE` on the same local channel you
already registered on.** No HTTPS, no cloud relay.

### How it actually works

The app's unlock action builds a tiny **JSON-RPC** body and sends it in a SIP `MESSAGE` (the
SIP "instant message" / chat method) toward the door's own SIP address — the same
`sip:<sip-user>@<sip-domain>` you register against, *not* the LAN IP. The body names a method and
the target actuator:

```jsonc
// SIP MESSAGE body — method + which actuator, nothing more
{ "jsonrpc": "2.0", "id": <n>,
  "method": "<lock-set-status>",            // from the decompiled call path
  "params": { "receiver": "<actuator-addr>", // which relay: gate, lock, light…
              "status": "<on|open>" } }
```

- **Only the actuator address distinguishes targets.** The gate, the pedestrian lock and the
  courtesy light are the *same* command with a different `receiver` address. Those addresses come
  out of the device topology (read-only), not out of guessing.
- **It is an impulse / toggle**, not a stateful "locked/unlocked" — you are pulsing a relay, the
  same way the physical button does.

### The one real trap: a single registration per account (single-AOR)

The door accepts **only one active registration per SIP account**. If a background service is
already registered to catch rings (§9), a second client that registers to send the open command
will **evict the first** — and now nothing is listening for the doorbell. A second `REGISTER`
from a new contact is simply dropped.

The way through is to **not** open a second registration at all: send the `MESSAGE` *through the
client that is already registered*. In this project the ring-catcher (§9) exposes a tiny local
command channel (an MQTT topic), and the open request is handed to it; it emits the SIP `MESSAGE`
from its existing dialog. One registration, two jobs.

> No real actuator address, method name, CN or SIP identity is published here — those are
> device-specific and live only in the owner's vault (§7). What transfers is the shape: *decompile
> the unlock path → it's a local SIP `MESSAGE` with a JSON-RPC body → send it from your one
> registered client.*

---

## 9. Catching the ring and grabbing a photo

A registration is only useful if something *listens*. Keep a `pjsua`-based client registered as a
background service (one systemd unit, auto-restart) so it is always ready for the next call. When
someone presses the button, the door sends an incoming SIP `INVITE` to the registered account —
that INVITE *is* the "someone rang" event. Surface it however your home-automation system likes (a
binary sensor flipping to *ringing*, an MQTT message, a notification).

The interesting part is grabbing the visitor's face **without ever answering**, and the two
gotchas that cost the most time — both learned by *measuring*, not guessing.

### Gotcha 1 — the media is early-media (183), never a confirmed call

The door offers video the moment it rings: it sends `183 Session Progress` with media, and starts
streaming **before** (and whether or not) you answer. So you do **not** send `200 OK` — you let the
early-media flow and record it. Point pjsua's AVI recorder at the incoming stream and you get a
short clip per ring, no call ever confirmed, the physical handset still free to ring.

Record **one AVI per call** (rotate a fresh file on each INVITE), so a ring never overwrites the
previous visitor's clip while you are still turning it into a photo.

### Gotcha 2 — the AVI's declared frame rate is a lie; seek by frame index, not seconds

This is the one that will waste your afternoon. The AVI pjsua writes **declares 15 fps in its
header but actually encodes ~9 fps** (measured: ~268 frames over ~29.7 s). So any
`ffmpeg -ss <seconds>` seek lands on the wrong frame — ask for "2.5 s in" and you get a frame from
*much* later, i.e. the visitor already walking out of shot.

**Extract by frame *index*, not by time:**

```bash
# WRONG: -ss trusts the lying 15 fps header and overshoots
# ffmpeg -ss 2.5 -i ring.avi -frames:v 1 out.jpg

# RIGHT: pick an absolute frame number; n starts at 0
ffmpeg -i ring.avi -vf "select='eq(n,10)'" -frames:v 1 -q:v 2 out.jpg
```

Frame 10 (~4 s after the `183`, once the stream has stabilised and the visitor is centred) gives a
clean face. Verify the real rate yourself before trusting any timing:

```bash
ffprobe -v error -select_streams v:0 \
  -show_entries stream=nb_frames,avg_frame_rate,r_frame_rate,duration \
  -of default=nw=1 ring.avi
```

If `avg_frame_rate` and the header `r_frame_rate` disagree, believe `nb_frames` and index from
there. A short fallback — `-sseof -0.5` for the last frame — covers rings so brief the stream is
cut before frame 10 exists.

### Wiring it into Home Assistant over MQTT

Decode the chosen frame to JPEG in a worker thread (a small bounded queue is enough — rings are
rare and short), then hand everything to Home Assistant **over MQTT** — no custom integration, no
polling, no cloud. The glue is **MQTT Discovery**: the background client publishes one *retained*
config message per entity, and HA auto-creates the devices. You publish three things, all under one
MQTT device so they group neatly in HA:

1. **A binary sensor** — "someone is ringing" — flipped from the incoming `INVITE`.
2. **A camera** — the visitor photo, published as a raw JPEG on an image topic.
3. **The open buttons** (§8) — gate / lock / light — each a `button` whose command topic the client
   subscribes to, so a press in HA becomes the local SIP `MESSAGE`.

Discovery config for the camera and one button (placeholders only — pick your own topic prefix and
IDs):

```jsonc
// retain=true, topic: homeassistant/camera/<node>/photo/config
{ "name": "Doorbell snapshot",
  "unique_id": "<node>_photo",
  "topic": "<prefix>/<node>/photo",          // raw JPEG bytes published here on each ring
  "device": { "identifiers": ["<node>"], "name": "Door station",
              "manufacturer": "BTicino/Legrand", "model": "EasyKit" } }

// retain=true, topic: homeassistant/button/<node>/gate/config
{ "name": "Open gate",
  "unique_id": "<node>_gate",
  "command_topic": "<prefix>/<node>/open",   // client subscribes; a press -> SIP MESSAGE (§8)
  "payload_press": "gate",
  "device": { "identifiers": ["<node>"] } }
```

Then at runtime the client just:

- publishes JPEG bytes to `<prefix>/<node>/photo` (the camera updates instantly), and
- on a message arriving at `<prefix>/<node>/open`, emits the matching SIP `MESSAGE` from its one
  registered dialog (§8) — so an HA button, an automation, or a dashboard tap opens the door
  locally.

The whole path — ring → early-media AVI → frame by index → JPEG → MQTT camera in HA, and HA button
→ MQTT → local SIP `MESSAGE` → relay — runs on your LAN, with the cloud never in the loop, and is
**proven in production**.

![The reclaimed door station in Home Assistant: an MQTT device exposing the gate / stairwell-light /
gate-impulse buttons, the ring binary sensor, the on-ring camera snapshot, and an activity log of
real commands — all local.](docs/ha-device.png)

*The door station as a native MQTT device in Home Assistant — opening buttons, ring sensor, on-ring
snapshot (blurred here), and a log of real commands. No cloud. (The camera thumbnail is deliberately
blurred; everything else is the actual device page.)*

> Why MQTT Discovery rather than a REST/template sensor: the client *pushes* on an event (a ring is
> rare and instantaneous), retained config survives an HA restart, and the camera takes raw JPEG on
> a topic with no extra plumbing. It is the lightest honest way to get a *pushed* image and a
> *command* path into HA.

---

## 10. Work in progress — where this is going

The hard parts are done and proven: identity extraction, the static-ECDH TLS wall, local
registration, **photo on ring (§9)**, and **local door opening (§8)**. What remains is polish, not
cryptography:

- **Full live media**, not just a snapshot — negotiate the INVITE's SDP for a continuous view.
- **Richer event history** — log every INVITE and its outcome for a who-rang-when record.
- **Night-time robustness** — confirm the on-ring photo timing holds with the IR illuminator at
  night (the frame-index tuning in §9 was measured in daylight).

These land as separate, documented commits.

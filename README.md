# Reclaiming a BTicino / Legrand EasyKit door station on the local network

> **Status: work in progress.** The reverse-engineering chain below is proven end to end:
> the TLS client identity is recovered from the vendor app, the mutual-TLS handshake to the
> door station succeeds, and a SIP `REGISTER` is accepted (`200 OK`) — all on the LAN, with no
> cloud. What is **not** done yet is turning that registration into something useful inside a
> home-automation system (catching the incoming call, pulling the video, logging rings). Those
> parts are sketched at the end and will land as later commits.

> **What this does — and what it deliberately does not.** This project is about *reading* the
> door station: knowing when someone rings, getting the video/audio stream, keeping a history of
> events. **It does not open the door.** On this hardware the gate/lock command does not travel
> over the local SIP channel at all — it goes out to the vendor cloud over HTTPS (see
> [§8](#8-what-this-does-not-do-opening-the-door)). So there is no "unlock" here to misuse, by
> design and by fact.

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

## The short version

A BTicino/Legrand EasyKit door station is, under the vendor skin, a SIP endpoint protected by
**mutual TLS**. To talk to it locally you need to present a client certificate it trusts — and that
certificate, its private key, and the SIP account parameters are all sitting inside the companion
Android app, encrypted at rest.

The chain is:

1. **Find where the app decrypts its own identity** and hook that point, so the plaintext key +
   cert + SIP parameters fall out — [§2](#2-recovering-the-tls-identity-from-the-app-frida) and
   [§3](#3-the-re-provisioning-trick).
2. **Discover the door's TLS constraints** — it only accepts a handful of *static-ECDH* cipher
   suites, which modern OpenSSL has removed — so you must build the client on **mbedTLS 3.6.x**
   — [§4](#4-the-tls-wall-static-ecdh-and-why-openssl-wont-do).
3. **Prove the handshake** with a raw TLS client — [§5](#5-proving-the-handshake).
4. **Register over SIP-TLS** with PJSIP, working around a certificate-name mismatch — [§6](#6-registering-over-sip-tls).

After that you have a registered local endpoint, which is the foundation for everything the
"work in progress" section describes.

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

## 2. Recovering the TLS identity from the app (Frida)

The app stores its identity encrypted and decrypts it in memory when it needs to connect. The
clean way to capture it is to hook the decryption primitive and print what comes out — no need to
reverse the key-derivation or the storage format at all.

On Android, this almost always funnels through `javax.crypto.Cipher`. The trick is to hook
`doFinal` **and only act when the cipher is in DECRYPT mode** — otherwise you also dump everything
the app *encrypts*, which is noise.

```js
// frida -U -f com.<vendor>.<app> -l dump_identity.js
// Hook Cipher.doFinal, print plaintext ONLY when the cipher was init'd to DECRYPT.
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

What falls out, across a few decrypt calls, is the complete client identity:

- an **EC P-256 private key** (SEC1 / PKCS#8),
- the matching **X.509 client certificate**,
- the **CA chain** the server expects,
- the **SIP account parameters** — username, domain/realm, password, the registrar address.

> **Why hook `doFinal` and not the file read?** The blob on disk is ciphertext; the key to decrypt
> it is itself derived at runtime. Hooking the decrypt output skips all of that — you get the
> finished plaintext the app was about to use, regardless of how it was stored or keyed.

---

## 3. The re-provisioning trick

There's a catch: the app only decrypts the identity when it has a reason to — typically during
**initial provisioning/pairing**, or the first connection after a fresh install. If you attach
Frida to an app that already has everything cached and idle, `doFinal` may never fire with the
material you want.

The reliable way to force the decrypt is to make the app **provision again**: clear its data (or
reinstall), attach the hook *before* first launch (`frida -f …`, spawn-gating, not attach), then
walk through the pairing/login flow. The identity is decrypted as part of coming online, right in
front of your hook.

This is also why **spawn mode matters** — you must be hooked before the app's first crypto call,
so launch it *under* Frida rather than attaching after the fact.

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

```
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

```
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

## 8. What this does **not** do: opening the door

It's worth being blunt about the limit, because it's the first thing people assume.

**The gate/lock-release command is not on the local SIP channel.** On this hardware, "open the
door" is sent by the app to the **vendor cloud over HTTPS**, and the cloud relays it. It is not a
SIP message you can replay locally once you're registered. Attempts to drive the lock purely over
the local SIP session are a dead end — the registration gives you *presence and media*, not the
actuator.

So this project is scoped to what the local channel genuinely exposes: **the call itself** (someone
is ringing), **the stream**, and **the event history**. Opening the door stays with the vendor path,
and this repo makes no attempt to forge or replay it.

---

## 9. Work in progress — where this is going

With a registered endpoint, the remaining pieces are integration, not cryptography:

- **"Someone rang" as a trigger.** A ring arrives as an incoming SIP `INVITE` to the registered
  account. Catch that INVITE and surface it as an event (a notification, a sensor flipping to
  *ringing*) in a home-automation system.
- **Video / audio.** Negotiate the media from the INVITE's SDP and pull the stream, for a live view
  or a snapshot on ring.
- **Event history.** Log each INVITE (and its outcome) so there's a record of who rang and when —
  the thing the vendor app keeps to itself.
- **A persistent local client.** Keep a `pjsua`-based endpoint registered as a background service so
  it's always ready to catch the next call, instead of a manual run.

These will be filled in as separate, documented commits. The point of this first drop is the part
that was genuinely hard and is now **proven**: getting the identity out, beating the static-ECDH TLS
wall, and registering locally without the cloud.

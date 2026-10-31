// 20-dump-identity.js — Frida hook that captures the TLS client identity the app decrypts.
//
// Section 3. The cert + key are stored encrypted at rest; the app decrypts them in memory when
// it connects. We hook javax.crypto.Cipher.doFinal and print the plaintext ONLY when the cipher
// was initialised in DECRYPT mode (mode 2) — otherwise we'd also dump everything it ENCRYPTS.
//
// Load it with spawn (not attach), so we are present before the app's first crypto call:
//   frida -U -f <pkg> -l 20-dump-identity.js
//
// Then walk the pairing/provisioning flow in the app: the identity is decrypted as part of
// coming online. Copy the EC private key / X.509 cert / CA chain / SIP params out of the output.

Java.perform(function () {
  const Cipher = Java.use('javax.crypto.Cipher');
  const DECRYPT_MODE = 2;

  // Remember the mode each Cipher instance was initialised with (several init overloads exist).
  ['int,java.security.Key',
   'int,java.security.Key,java.security.spec.AlgorithmParameterSpec',
   'int,java.security.Key,java.security.AlgorithmParameters',
   'int,java.security.cert.Certificate'].forEach(function (sig) {
    try {
      const ov = Cipher.init.overload.apply(Cipher.init, sig.split(','));
      ov.implementation = function () {
        this._mode = arguments[0];
        return ov.apply(this, arguments);
      };
    } catch (e) { /* overload absent on this Android level — ignore */ }
  });

  function dump(tag, out) {
    if (this._mode !== DECRYPT_MODE || out === null) return;
    const b = Java.array('byte', out);
    console.log('\n--- doFinal DECRYPT (' + tag + ', ' + b.length + ' bytes) ---');
    // Identity blobs are usually PEM / ASN.1 / JSON — print hex, it's easy to spot and carve.
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

  console.log('[*] hooked javax.crypto.Cipher.doFinal (DECRYPT only). Now walk the pairing flow.');
});

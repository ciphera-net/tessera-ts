# @ciphera-net/tessera

Browser SDK for the Tessera authentication and vault system.

> **Status: PRIVATE — do not distribute until external audit is complete.**

---

## What it is

`@ciphera-net/tessera` is a browser-first TypeScript SDK that implements:

- **OPAQUE (RFC 9807) password authentication** — the password never reaches the server; only the SRP-style verifier (OPAQUE password file) is stored there. The `export_key` produced by the OPAQUE handshake is used exclusively to wrap the vault master key (VMK), then zeroed.
- **Argon2id blind index** — a deterministic, pseudonymous lookup key derived from the email address (Argon2id/v0x13/m=64 MiB/t=3/p=1, domain-separated salt). Used as the server-side `credentialId`; the plaintext email never hits the database.
- **AES-256-GCM vault** — a two-layer envelope (wrapped DEK under a per-context KEK). Context is required on every seal/open call and is bound into the key derivation and AAD; it is never stored in the envelope.
- **BIP-39 (24-word / 256-bit) recovery phrase** — the mnemonic entropy is used directly as the VMK-wrap secret (no PBKDF2 indirection). Shown to the user once at registration.
- **WebAuthn-PRF passwordless unlock** — additive. The password and recovery phrase remain valid at all times; an authenticator without PRF support simply cannot enroll the passkey path.

The SDK is byte-for-byte interoperable with **tessera-go** (the Go server SDK) and the **Rust sidecar**. All three implementations share the pinned algorithm constants in the canonical conformance kit at `ciphera-net/tessera` (`conformance/schema.md` + `conformance/CONFORMANCE.md`) and are validated by cross-language parity vectors in `conformance/vectors/`.

---

## Install

```
npm i @ciphera-net/tessera
```

> The package is currently `"private": true`. It is not published to npm. Install from the monorepo or a local path until the audit clears.

**Peer requirement:** the SDK is transport-agnostic. Your application must supply a `Transport` implementation that relays OPAQUE blobs and VMK-wrap storage to your backend (which fronts tessera-go → the Rust sidecar). See [Transport](#transport) below.

---

## Quick start

### 1. Initialize the WASM module

```ts
import { init, Tessera } from '@ciphera-net/tessera';

// Must resolve before any WASM-backed API (blind index, OPAQUE handles).
// Safe to call multiple times — idempotent.
await init();
```

**Browser:** loads the `web` wasm-pack target (ESM + async fetch of the `.wasm` binary).  
**Node (tests/SSR):** loads the `nodejs` wasm-pack target (CommonJS, auto-initialized on require — no separate async init needed, but calling `init()` is still safe and recommended for uniform code paths).

### 2. Implement Transport

```ts
import type { Transport } from '@ciphera-net/tessera';

const transport: Transport = {
  // OPAQUE registration — phase 1: send the client request, receive the server response.
  async registerStart({ requestB64, credentialId }) {
    const res = await fetch('/auth/register/start', {
      method: 'POST',
      body: JSON.stringify({ requestB64, credentialId }),
    });
    return res.json(); // { responseB64: string }
  },

  // OPAQUE registration — phase 2: send the finalization upload. The server stores the password
  // file; it is never returned to the browser.
  async registerFinish({ credentialId, uploadB64 }) {
    await fetch('/auth/register/finish', {
      method: 'POST',
      body: JSON.stringify({ credentialId, uploadB64 }),
    });
  },

  // OPAQUE login — phase 1. passwordFile is nullable: an unknown account passes null to the
  // sidecar for a timing-safe dummy response. The browser cannot distinguish existing from
  // non-existing accounts.
  async loginStart({ requestB64, credentialId }) {
    const res = await fetch('/auth/login/start', {
      method: 'POST',
      body: JSON.stringify({ requestB64, credentialId }),
    });
    return res.json(); // { loginId: string; responseB64: string }
  },

  // OPAQUE login — phase 2. Returns the OPAQUE session key (opaque to the server).
  async loginFinish({ loginId, finalizationB64 }) {
    const res = await fetch('/auth/login/finish', {
      method: 'POST',
      body: JSON.stringify({ loginId, finalizationB64 }),
    });
    return res.json(); // { sessionKeyB64: string }
  },

  // Recovery password reset — replaces the server-side password file after the OPAQUE re-enrollment
  // driven by recoverWithPhrase().resetPassword(). Vault content is untouched.
  async replacePasswordFile({ credentialId, uploadB64 }) {
    await fetch('/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ credentialId, uploadB64 }),
    });
  },

  // Store one or more VMK-wrap blobs (opaque bytes to the server), keyed by method name.
  // method names used by the SDK: "opaque", "recovery", "webauthn".
  async putWraps({ credentialId, wraps }) {
    await fetch('/auth/wraps', {
      method: 'PUT',
      body: JSON.stringify({ credentialId, wraps }),
    });
  },

  // Fetch a single VMK-wrap blob by method. Returns null if the method has no stored wrap.
  async getWrap({ credentialId, method }) {
    const res = await fetch(`/auth/wraps/${credentialId}/${method}`);
    if (res.status === 404) return null;
    return res.json(); // { blobB64: string } | null
  },
};
```

All OPAQUE blobs exchanged with the server (`requestB64`, `responseB64`, `uploadB64`, `finalizationB64`, `sessionKeyB64`) are **base64-STANDARD** strings. VMK-wrap blobs (`blobB64`) are also base64-STANDARD (opaque byte sequences; not OPAQUE wire format).

### 3. Register

```ts
const t = new Tessera(transport);

// password must be a Uint8Array — the WASM OPAQUE layer operates on bytes.
const password = new TextEncoder().encode('correct horse battery staple');

const { recoveryPhrase } = await t.register({ email: 'alice@example.com', password });

// Show recoveryPhrase to the user EXACTLY ONCE and prompt them to write it down.
// The SDK does not store it. The string is immutable (JS strings cannot be zeroed —
// see Security model below).
console.log(recoveryPhrase); // 24 BIP-39 words
```

`register` performs: blind-index → OPAQUE enrollment → VMK generation → wrap under `export_key` (method `"opaque"`) + fresh recovery entropy (method `"recovery"`) → `putWraps`. The `export_key` and recovery entropy are zeroed in a `finally` block before the call resolves.

### 4. Login

```ts
const session = await t.login({ email: 'alice@example.com', password });

// session.sessionKeyB64 — the OPAQUE session key (string | null).
// null on recovery and passkey paths (no OPAQUE handshake ran).
console.log(session.sessionKeyB64);

// Seal a record.
const envelope = await session.vault.seal('address', new TextEncoder().encode('123 Main St'));

// Open it later. Wrong key, wrong context, or tampered bytes all throw the same error
// (no decryption oracle — see Security model).
const plaintext = await session.vault.open('address', envelope);
```

### 5. Recovery

```ts
const rec = await t.recoverWithPhrase({
  email: 'alice@example.com',
  phrase: 'word1 word2 ... word24', // the 24-word BIP-39 phrase from registration
});

// rec is a RecoverySession — a Session extended with resetPassword.
// rec.sessionKeyB64 is null (no OPAQUE handshake on this path).
// Vault is fully accessible while the session is alive.

// Optionally reset the password (re-keys auth; vault content is never re-encrypted).
await rec.resetPassword(new TextEncoder().encode('new password'));
// After resetPassword, the recovery secret is zeroed; calling resetPassword again will fail.
```

### 6. Passkey (WebAuthn-PRF)

```ts
import { isPasskeySupported, evaluatePrf } from '@ciphera-net/tessera';

// Conservative support probe (no user gesture needed, no credential created).
// Definitive PRF availability is only known after a real ceremony returns results.
if (await isPasskeySupported()) {
  // Enable: creates a new WebAuthn credential and wraps the VMK under the PRF output.
  // The app owns rpId, challenge, and userId — the SDK does not.
  await t.enablePasskey({
    email: 'alice@example.com',
    password, // re-authenticates via OPAQUE (required — non-extractable VMK cannot be re-wrapped)
    prf: () =>
      evaluatePrf({
        create: true,
        rpId: 'example.com',
        rpName: 'Example',
        userId: crypto.getRandomValues(new Uint8Array(16)),
        userName: 'alice@example.com',
        challenge: crypto.getRandomValues(new Uint8Array(32)),
      }),
  });

  // Unlock on a later visit — no password needed.
  const session = await t.unlockWithPasskey({
    email: 'alice@example.com',
    prf: () =>
      evaluatePrf({
        create: false,
        rpId: 'example.com',
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentialIds: [storedCredentialId], // optional; omit for discoverable credentials
      }),
  });
  // session.sessionKeyB64 is null — no OPAQUE handshake on the passkey path.
}
```

`PrfProvider` is `() => Promise<Uint8Array>` — a zero-argument async function that runs the WebAuthn ceremony and returns exactly 32 bytes. The SDK zeroes the returned buffer after use. Return a fresh buffer on each call; do not share or reuse it.

`evaluatePrf` uses a pinned PRF eval input (`"tessera/prf/v1"` UTF-8) so the PRF output is stable across `enablePasskey` and `unlockWithPasskey`. This input is an SDK internal — the app does not need to supply it.

---

## Transport

The full `Transport` interface (7 methods):

| Method | Direction | Description |
|---|---|---|
| `registerStart({ requestB64, credentialId })` | client → server | OPAQUE reg phase 1 |
| `registerFinish({ credentialId, uploadB64 })` | client → server | OPAQUE reg phase 2; returns `void` |
| `loginStart({ requestB64, credentialId })` | client → server | OPAQUE login phase 1; returns `{ loginId, responseB64 }` |
| `loginFinish({ loginId, finalizationB64 })` | client → server | OPAQUE login phase 2; returns `{ sessionKeyB64 }` |
| `replacePasswordFile({ credentialId, uploadB64 })` | client → server | password reset after recovery; returns `void` |
| `putWraps({ credentialId, wraps })` | client → server | store VMK-wrap blobs by method name; returns `void` |
| `getWrap({ credentialId, method })` | client ← server | fetch one VMK-wrap blob; returns `{ blobB64: string } \| null` |

`passwordFile` on the server side is `string | null` — `null` for an unknown account. The server passes it to the sidecar for a timing-safe dummy OPAQUE response. The browser cannot distinguish an existing from a non-existing account.

---

## The vault

```ts
// seal — encrypts plaintext and returns an opaque envelope (Uint8Array).
const envelope: Uint8Array = await session.vault.seal(context, plaintext);

// open — decrypts and authenticates. Returns the original plaintext.
const plaintext: Uint8Array = await session.vault.open(context, envelope);
```

**`context`** (a non-empty string) is mandatory on every call. It:

- Names the record type, e.g. `"address"`, `"totp"`, `"note"`.
- Is fed into the HKDF info string (`"tessera/vault/v1/record/" + context`), deriving an independent KEK per record type.
- Is bound as AAD into both GCM operations (wrap and content), preventing context substitution.
- Is **not stored** in the envelope — the caller must supply the same context to `open` that was used in `seal`.

An envelope sealed under `"address"` cannot be opened under `"totp"` — wrong-context is indistinguishable from wrong-key or tampered bytes, and will throw.

**Thrown errors** (all from the same error module):

| Class | When |
|---|---|
| `UnsupportedVersionError` | envelope version byte ≠ `0x01` |
| `MalformedEnvelopeError` | envelope too short to parse |
| `EmptyVaultKeyError` | zero-length key material passed |
| `EmptyContextError` | context is an empty string |

For wrong-key, wrong-context, and GCM tag failure, `open` throws a generic `Error` — there is no specific class that reveals which check failed (no decryption oracle).

---

## Crypto parameters (pinned)

These constants are fixed across all SDK implementations (TS, Go, Rust). Any change requires a new version label and a migration.

### Blind index

| Parameter | Value |
|---|---|
| KDF | Argon2id |
| Version | `0x13` (19) — must be specified explicitly |
| Memory (m) | `65536 KiB` (64 MiB) |
| Time (t) | `3` |
| Parallelism (p) | `1` |
| Output length | 32 bytes |
| Salt | `"tessera/blind-index/v1"` (UTF-8, no NUL) |
| Encoding | base64url **unpadded** (`+→-`, `/→_`, no `=`) |

Email normalization (applied in order before hashing): trim whitespace → lowercase.

`p=1` is pinned because common browser/WASM Argon2 builds run single-threaded and may silently clamp `p>1` to `p=1`, yielding a different output from a native multi-lane build.

### OPAQUE KSF

The OPAQUE password-hardening KSF uses the same Argon2id suite, applied at `register_finish` and `login_finish` on the client:

| Parameter | Value |
|---|---|
| KDF | Argon2id `0x13` |
| Memory (m) | `65536 KiB` (64 MiB) |
| Time (t) | `3` |
| Parallelism (p) | `1` |

OPAQUE blobs are encoded as **base64-STANDARD** (not base64url) on the wire.

### Vault envelope v1

```
[0x01][nonceW 12B][AES-256-GCM(KEK, DEK) = 48B][nonceC 12B][AES-256-GCM(DEK, msg)]
```

Minimum size (empty plaintext): 89 bytes.

KEK derivation:

```
KEK = HKDF-SHA-256(
  IKM  = vaultKey (VMK),
  salt = 32 zero bytes,   // RFC 5869 §2.2 nil-salt → HashLen zeros; SHA-256 HashLen = 32
  info = "tessera/vault/v1/record/" ‖ utf8(context),
  L    = 32
)
```

The 32-zero salt is intentional and matches Go's `hkdf.Key(sha256.New, vaultKey, nil, ...)`. Using a genuinely zero-length salt derives a different KEK and breaks interoperability.

AAD (bound into both GCM operations):

```
AAD = [0x01] ‖ utf8(context)
```

---

## Security model and honest limits

### What the SDK does

- The vault master key (VMK) is held as a **non-extractable `CryptoKey`** inside the `Session` object. `extractable: false` prevents `crypto.subtle.exportKey` from returning the raw bytes.
- The OPAQUE `export_key` (64 bytes) and the recovery entropy (32 bytes) transit WASM/JS linear memory transiently during unlock. They are zeroed in `finally` blocks immediately after the VMK is wrapped or unwrapped and do not persist across calls. They never cross the network.
- VMK-wrap blobs stored server-side are opaque byte sequences. The server holds no plaintext passwords and no vault keys.

### What the SDK cannot guarantee

**Non-extractable is an API-layer guard, not process isolation.** A compromised page (XSS, malicious dependency, compromised browser extension) can still *use* the non-extractable key to seal/open arbitrary records. It cannot export the raw VMK bytes via `exportKey`, but it can call `session.vault.seal` and `session.vault.open` freely. Non-extractable does not defend against a compromised execution context.

**Memory zeroing is best-effort.** The `export_key` and raw VMK transit WASM/JS linear memory and are zeroed after use, but the JavaScript runtime and the JIT compiler may copy values to internal buffers (AES round-key schedules, GC copying collectors) that are not reachable for zeroing. These copies are transient and never written to persistent storage or the network, but they cannot be guaranteed erased.

**The recovery phrase string cannot be zeroed.** JavaScript strings are immutable. `newRecoveryPhrase()` returns a `string`; the SDK derives the 32-byte entropy from it and zeroes that buffer, but the phrase string itself lives until it is garbage-collected. Minimize its lifetime: store it only long enough to display it to the user, then discard all references.

**Constant-time is not fully achievable in TS/WASM.** JavaScript engines make no constant-time guarantees for arithmetic or memory access. The SDK relies on the underlying OPAQUE and AES-GCM primitives (Rust sidecar, WebCrypto) for timing safety; the TS orchestration layer is not constant-time.

**WebAuthn-PRF is additive.** Enrolling a passkey does not remove the password or recovery paths. An attacker who compromises the password can still log in even if the user has a passkey. This is intentional — the passkey path is a convenience unlock, not a security upgrade of the authentication factor.

**`open` collapses all failure modes into one error.** Wrong key, wrong context, and GCM tag failure all result in a generic decryption error. This is intentional — a caller cannot tell which check failed, so there is no decryption oracle.

---

## Testing and status

```bash
cd packages/tessera-ts

# Run unit and parity tests (Node, no browser needed).
npm test
```

Tests run with **vitest**. The parity test suite (`test/vectors.test.ts`) validates byte-exact blind-index vectors and vault open-parity vectors against the Go-generated snapshots in the canonical kit (`ciphera-net/tessera` → `conformance/vectors/`).

Tests that require the **tessera-go sidecar** (OPAQUE handshake, recovery flow, passkey flow) read the sidecar binary path from `TESSERA_SIDECAR_BIN`. They are skipped automatically when the variable is unset.

```bash
TESSERA_SIDECAR_BIN=/path/to/tessera-sidecar npm test
```

Cross-language parity vectors are the canonical conformance kit in `ciphera-net/tessera` (`conformance/vectors/blind-index.json`, `conformance/vectors/vault.json`) alongside `conformance/schema.md` + `conformance/CONFORMANCE.md`, the authoritative contract for all pinned constants. The Go generator at `tessera-go/harness/vectors/gen_go.go` regenerates the files and performs an in-process round-trip assertion before writing output.

A Playwright browser matrix (real WebAuthn virtual-authenticator, full in-browser WASM path) is a planned follow-up and is not yet part of the CI suite.

Current test suite: **44 tests across 10 files**, all passing.

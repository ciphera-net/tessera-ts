// WebCrypto vault: seal/open a record under a per-context key, BYTE-IDENTICAL to tessera-go/vault.go.
// Envelope v1: [0x01][nonceW 12][AES-256-GCM(KEK, DEK)=48][nonceC 12][AES-256-GCM(DEK, msg)].
//   KEK = HKDF-SHA256(IKM=vaultKey, salt=32 zero bytes, info="tessera/vault/v1/record/"+context, L=32)
//   DEK = random 32 bytes;  AAD = [0x01] ‖ utf8(context) on BOTH GCM ops;  context REQUIRED, NOT stored.
import { utf8, wcView } from './encoding.js';
import {
  EmptyContextError,
  EmptyVaultKeyError,
  MalformedEnvelopeError,
  UnsupportedVersionError,
} from './errors.js';

const VERSION = 0x01;
const NONCE_LEN = 12;
const TAG_LEN = 16;
const DEK_LEN = 32;
const WRAPPED_DEK_LEN = DEK_LEN + TAG_LEN; // 48
const MIN_ENVELOPE = 1 + NONCE_LEN + WRAPPED_DEK_LEN + NONCE_LEN + TAG_LEN; // 89
const KEK_INFO_BASE = 'tessera/vault/v1/record/';
// SHA-256 HashLen. Go's hkdf.Key(nil salt) expands to a HashLen-zero salt (RFC 5869 §2.2); we mirror
// that EXACTLY with an explicit 32-zero salt. If the HKDF hash ever changes, this MUST change with it
// or KEK derivation silently diverges from Go.
const HKDF_SALT_LEN = 32;
const subtle = globalThis.crypto.subtle;

// A vault key is specifically an HKDF CryptoKey (deriveKey-capable). Branding it makes passing an
// AES-GCM/other key a COMPILE error instead of a runtime DOMException inside deriveKEK.
export type VaultKey = CryptoKey & { readonly __tesseraVaultKey: unique symbol };

// AAD = versionByte ‖ utf8(context), bound into BOTH GCM ops (downgrade/substitution resistance).
function aad(context: string): Uint8Array {
  const c = utf8(context);
  const out = new Uint8Array(1 + c.length);
  out[0] = VERSION;
  out.set(c, 1);
  return out;
}

// KEK = HKDF-SHA256(vaultKey, salt=32 zero bytes, info=KEK_INFO_BASE+context, 32B), non-extractable.
// 32 zero bytes explicitly matches Go's nil-salt → RFC 5869 HashLen-zeros expansion.
async function deriveKEK(vaultKey: VaultKey, context: string): Promise<CryptoKey> {
  return subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: wcView(new Uint8Array(HKDF_SALT_LEN)),
      info: wcView(utf8(KEK_INFO_BASE + context)),
    },
    vaultKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** Import raw vault-key material (e.g. the VMK) as a non-extractable HKDF base key. */
export async function importVaultKey(raw: Uint8Array): Promise<VaultKey> {
  if (raw.length === 0) throw new EmptyVaultKeyError();
  return (await subtle.importKey('raw', wcView(raw), 'HKDF', false, ['deriveKey'])) as VaultKey;
}

/** Seal plaintext under a fresh DEK wrapped by a per-context KEK. context is REQUIRED and not stored. */
export async function seal(
  vaultKey: VaultKey,
  context: string,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  if (!context) throw new EmptyContextError();
  const a = aad(context);
  const kek = await deriveKEK(vaultKey, context);

  const dekRaw = crypto.getRandomValues(new Uint8Array(DEK_LEN));
  try {
    const dek = await subtle.importKey('raw', wcView(dekRaw), 'AES-GCM', false, ['encrypt']);

    const nonceW = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
    const wrappedDEK = new Uint8Array(
      await subtle.encrypt({ name: 'AES-GCM', iv: wcView(nonceW), additionalData: wcView(a) }, kek, wcView(dekRaw)),
    );

    const nonceC = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
    const ct = new Uint8Array(
      await subtle.encrypt({ name: 'AES-GCM', iv: wcView(nonceC), additionalData: wcView(a) }, dek, wcView(plaintext)),
    );

    const out = new Uint8Array(1 + NONCE_LEN + wrappedDEK.length + NONCE_LEN + ct.length);
    let o = 0;
    out[o++] = VERSION;
    out.set(nonceW, o);
    o += NONCE_LEN;
    out.set(wrappedDEK, o);
    o += wrappedDEK.length;
    out.set(nonceC, o);
    o += NONCE_LEN;
    out.set(ct, o);
    return out;
  } finally {
    dekRaw.fill(0); // wipe the raw DEK unconditionally (mirrors Go's `defer wipe(dek)`), even on error
  }
}

/** Open reverses seal. Same generic error for wrong-key/tamper/short; distinct UnsupportedVersion. */
export async function open(
  vaultKey: VaultKey,
  context: string,
  envelope: Uint8Array,
): Promise<Uint8Array> {
  if (!context) throw new EmptyContextError();
  if (envelope.length < 1) throw new MalformedEnvelopeError();
  if (envelope[0] !== VERSION) throw new UnsupportedVersionError();
  if (envelope.length < MIN_ENVELOPE) throw new MalformedEnvelopeError();

  let o = 1;
  const nonceW = envelope.subarray(o, (o += NONCE_LEN));
  const wrappedDEK = envelope.subarray(o, (o += WRAPPED_DEK_LEN));
  const nonceC = envelope.subarray(o, (o += NONCE_LEN));
  const ct = envelope.subarray(o);

  const a = aad(context);
  const kek = await deriveKEK(vaultKey, context);
  // Nullable (not a sentinel): stays null if the wrap-decrypt throws before the DEK exists, so the
  // finally wipe is a safe no-op in that case.
  let dekRaw: Uint8Array | null = null;
  try {
    dekRaw = new Uint8Array(
      await subtle.decrypt({ name: 'AES-GCM', iv: wcView(nonceW), additionalData: wcView(a) }, kek, wcView(wrappedDEK)),
    );
    const dek = await subtle.importKey('raw', wcView(dekRaw), 'AES-GCM', false, ['decrypt']);
    // pt is a FRESH allocation (a copy out of WebCrypto), not a view into `envelope`; callers handling
    // sensitive plaintext own this buffer and may zero it after use.
    return new Uint8Array(
      await subtle.decrypt({ name: 'AES-GCM', iv: wcView(nonceC), additionalData: wcView(a) }, dek, wcView(ct)),
    );
  } catch {
    // One generic error for wrong-key / wrong-context / tamper (oracle resistance — matches Go, which
    // returns ErrMalformedEnvelope for ANY Open failure). UnsupportedVersion is handled above, before
    // this block, so it is never collapsed here.
    throw new MalformedEnvelopeError();
  } finally {
    dekRaw?.fill(0); // wipe the raw DEK unconditionally (mirrors Go's `defer wipe(dek)`)
  }
}

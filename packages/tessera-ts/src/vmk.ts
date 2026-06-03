// VMK (Vault Master Key) hierarchy. The long-lived vault key is a random 32-byte VMK held only as a
// non-extractable WebCrypto CryptoKey; it is WRAPPED once per unlock method (opaque / recovery /
// webauthn) so adding or resetting a method only re-wraps the VMK — the vault itself is never
// re-encrypted. Each wrap is a dedicated single-layer envelope (the payload is exactly the 32-byte
// VMK; no DEK indirection):
//   [0x01][nonce 12][AES-256-GCM(wrapKEK, VMK)=48]  = 61 bytes
//   wrapKEK = HKDF-SHA256(IKM=methodSecret, salt=32 zero bytes, info="tessera/vmk-wrap/v1/"+method, 32)
//   AAD     = [0x01] ‖ utf8("tessera/vmk-wrap/v1/"+method)  (binds version + method into the GCM tag)
// Wrap/unwrap is plain AES-GCM encrypt/decrypt (NOT WebCrypto wrapKey/unwrapKey): one universally
// supported path, and the same KEK works both directions.
import { utf8, wcView } from './encoding';
import { importVaultKey, type VaultKey } from './vault';
import { MalformedEnvelopeError } from './errors';

const subtle = globalThis.crypto.subtle;
const VERSION = 0x01;
const NONCE_LEN = 12;
const TAG_LEN = 16;
const VMK_LEN = 32;
const WRAPPED_VMK_LEN = VMK_LEN + TAG_LEN; // 48 (AES-GCM ct ‖ tag)
const ENVELOPE_LEN = 1 + NONCE_LEN + WRAPPED_VMK_LEN; // 61

export type UnlockMethod = 'opaque' | 'recovery' | 'webauthn';

function wrapInfo(method: UnlockMethod): Uint8Array {
  return utf8('tessera/vmk-wrap/v1/' + method);
}
function wrapAad(method: UnlockMethod): Uint8Array {
  const m = wrapInfo(method);
  const out = new Uint8Array(1 + m.length);
  out[0] = VERSION;
  out.set(m, 1);
  return out;
}

// wrapKEK = HKDF-SHA256(methodSecret, salt=32 zeros, info, 32) as a non-extractable AES-GCM key with
// encrypt+decrypt usage (one KEK, both directions).
async function deriveWrapKEK(methodSecret: Uint8Array, method: UnlockMethod): Promise<CryptoKey> {
  const base = await subtle.importKey('raw', wcView(methodSecret), 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: wcView(new Uint8Array(32)), info: wcView(wrapInfo(method)) },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** Encrypt raw VMK bytes under a method secret → versioned envelope. The CALLER owns and must zero
 *  both `vmkRaw` and `methodSecret` after use (this fn does not zero its inputs). */
export async function wrapVmk(
  vmkRaw: Uint8Array,
  methodSecret: Uint8Array,
  method: UnlockMethod,
): Promise<Uint8Array> {
  // Derived OUTSIDE a catch on purpose: a bad secret at wrap (setup) time is a programming error that
  // should surface loudly, not an attacker-observable oracle (contrast unwrapVmkRaw below).
  const kek = await deriveWrapKEK(methodSecret, method);
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const ct = new Uint8Array(
    await subtle.encrypt({ name: 'AES-GCM', iv: wcView(nonce), additionalData: wcView(wrapAad(method)) }, kek, wcView(vmkRaw)),
  );
  const out = new Uint8Array(ENVELOPE_LEN);
  out[0] = VERSION;
  out.set(nonce, 1);
  out.set(ct, 1 + NONCE_LEN);
  return out;
}

/** Decrypt a VMK envelope → raw VMK bytes. CALLER MUST zero BOTH the returned buffer AND `methodSecret`
 *  after use. */
export async function unwrapVmkRaw(
  blob: Uint8Array,
  methodSecret: Uint8Array,
  method: UnlockMethod,
): Promise<Uint8Array> {
  if (blob.length !== ENVELOPE_LEN || blob[0] !== VERSION) throw new MalformedEnvelopeError();
  const nonce = blob.subarray(1, 1 + NONCE_LEN);
  const ct = blob.subarray(1 + NONCE_LEN);
  try {
    // Derive INSIDE the try so a bad methodSecret (e.g. zero-length → HKDF importKey DataError) also
    // collapses to MalformedEnvelope rather than leaking a raw DOMException (oracle resistance — any
    // unlock failure is indistinguishable, matching vault.open).
    const kek = await deriveWrapKEK(methodSecret, method);
    return new Uint8Array(
      await subtle.decrypt({ name: 'AES-GCM', iv: wcView(nonce), additionalData: wcView(wrapAad(method)) }, kek, wcView(ct)),
    );
  } catch {
    throw new MalformedEnvelopeError(); // wrong secret / wrong method / tamper — never distinguished
  }
}

/** Unlock: decrypt the envelope and import the VMK as a NON-extractable VaultKey (raw is zeroed).
 *  CALLER must zero `methodSecret` after this returns. */
export async function openVaultKey(
  blob: Uint8Array,
  methodSecret: Uint8Array,
  method: UnlockMethod,
): Promise<VaultKey> {
  const raw = await unwrapVmkRaw(blob, methodSecret, method);
  try {
    return await importVaultKey(raw);
  } finally {
    raw.fill(0);
  }
}

/** Generate a fresh VMK. Returns the non-extractable VaultKey (for vault ops) + the wrapped blobs.
 *  Raw VMK exists only transiently during setup, then is zeroed. */
export async function generateAndWrap(
  secrets: Partial<Record<UnlockMethod, Uint8Array>>,
): Promise<{ vmk: VaultKey; wraps: Partial<Record<UnlockMethod, Uint8Array>> }> {
  // No silent footgun: an empty map would mint an IRRECOVERABLE VMK (no wrap can ever unlock it).
  if (Object.keys(secrets).length === 0) {
    throw new Error('tessera: generateAndWrap requires at least one unlock method');
  }
  const raw = globalThis.crypto.getRandomValues(new Uint8Array(VMK_LEN));
  try {
    const wraps: Partial<Record<UnlockMethod, Uint8Array>> = {};
    for (const method of Object.keys(secrets) as UnlockMethod[]) {
      // `method` came from Object.keys(secrets), so secrets[method] is defined (the `!` is sound).
      wraps[method] = await wrapVmk(raw, secrets[method]!, method);
    }
    const vmk = await importVaultKey(raw);
    return { vmk, wraps };
  } finally {
    raw.fill(0);
  }
}

/** Add/replace an unlock method WITHOUT re-encrypting the vault: re-decrypt the VMK from an existing
 *  wrap (using a JUST-RE-AUTHENTICATED secret) and re-wrap it under the new method. Used by
 *  enablePasskey and resetPassword. The raw VMK is zeroed before returning. CALLER must zero
 *  `existing.secret` and `next.secret` after this returns. */
export async function rewrapForMethod(
  existing: { blob: Uint8Array; secret: Uint8Array; method: UnlockMethod },
  next: { secret: Uint8Array; method: UnlockMethod },
): Promise<Uint8Array> {
  const raw = await unwrapVmkRaw(existing.blob, existing.secret, existing.method);
  try {
    return await wrapVmk(raw, next.secret, next.method);
  } finally {
    raw.fill(0);
  }
}

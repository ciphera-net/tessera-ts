// High-level Tessera SDK. Orchestrates blind index → OPAQUE → VMK → vault, transport-agnostic. The
// 64-byte OPAQUE export_key and the 32-byte recovery entropy are used ONLY to wrap the VMK, then zeroed
// — they never persist and never cross the wire. The VMK is held as a non-extractable CryptoKey inside
// the returned Session; the raw VMK never leaves WASM/JS linear memory at rest.
import { blindIndexString } from './blindIndex';
import { loginOpaque, registerOpaque } from './opaque';
import { generateAndWrap, openVaultKey } from './vmk';
import { newRecoveryPhrase, recoverySecret } from './recovery';
import { open as vaultOpen, seal as vaultSeal, type VaultKey } from './vault';
import { fromBase64Std, toBase64Std } from './encoding';
import type { Transport } from './transport';

// VMK-wrap blobs are stored as standard base64 (they are opaque server storage, not OPAQUE wire blobs).
const b64 = toBase64Std;
const fromB64 = fromBase64Std;

export interface Session {
  // null on the recovery / passkey unlock paths: those do NOT run an OPAQUE handshake, so there is no
  // OPAQUE session key (nullable, NOT an empty-string sentinel — the consumer handles null).
  sessionKeyB64: string | null;
  vault: {
    seal(context: string, plaintext: Uint8Array): Promise<Uint8Array>;
    open(context: string, envelope: Uint8Array): Promise<Uint8Array>;
  };
}

function sessionFor(vmk: VaultKey, sessionKeyB64: string | null): Session {
  return {
    sessionKeyB64,
    vault: {
      seal: (context, plaintext) => vaultSeal(vmk, context, plaintext),
      open: (context, envelope) => vaultOpen(vmk, context, envelope),
    },
  };
}

export class Tessera {
  constructor(private readonly transport: Transport) {}

  /** Register: enroll OPAQUE, mint a VMK, wrap it under the password (export_key) and a fresh recovery
   *  phrase, store both wraps. Returns the recovery phrase to show the user ONCE. */
  async register({
    email,
    password,
  }: {
    email: string;
    password: Uint8Array;
  }): Promise<{ recoveryPhrase: string }> {
    const credentialId = blindIndexString(email);
    const { exportKey } = await registerOpaque(this.transport, credentialId, password);
    // Open the try IMMEDIATELY so exportKey is zeroed on ANY subsequent throw. recovEntropy is
    // nullable (derived inside) and zeroed only if it was created — no sentinel.
    let recovEntropy: Uint8Array | undefined;
    try {
      const recoveryPhrase = newRecoveryPhrase();
      recovEntropy = recoverySecret(recoveryPhrase);
      // The WHOLE 64-byte export_key is the 'opaque' wrap secret — do NOT slice it.
      const { wraps } = await generateAndWrap({ opaque: exportKey, recovery: recovEntropy });
      await this.transport.putWraps({
        credentialId,
        wraps: { opaque: b64(wraps.opaque!), recovery: b64(wraps.recovery!) },
      });
      return { recoveryPhrase };
    } finally {
      exportKey.fill(0);
      recovEntropy?.fill(0);
    }
  }

  /** Login: OPAQUE → export_key → unwrap the VMK (non-extractable) → Session with vault ops. */
  async login({ email, password }: { email: string; password: Uint8Array }): Promise<Session> {
    const credentialId = blindIndexString(email);
    const { exportKey, sessionKeyB64 } = await loginOpaque(this.transport, credentialId, password);
    try {
      const wrap = await this.transport.getWrap({ credentialId, method: 'opaque' });
      if (!wrap) throw new Error('tessera: no opaque VMK wrap for this account');
      const vmk = await openVaultKey(fromB64(wrap.blobB64), exportKey, 'opaque');
      return sessionFor(vmk, sessionKeyB64);
    } finally {
      exportKey.fill(0);
    }
  }
}

/** @internal Exposed for the recovery/passkey methods added in later tasks (not re-exported from index). */
export { sessionFor };

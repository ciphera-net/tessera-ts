// High-level Tessera SDK. Orchestrates blind index → OPAQUE → VMK → vault, transport-agnostic. The
// 64-byte OPAQUE export_key and the 32-byte recovery entropy are used ONLY to wrap the VMK, then zeroed
// — they never persist and never cross the wire. The VMK is held as a non-extractable CryptoKey inside
// the returned Session; the raw VMK never leaves WASM/JS linear memory at rest.
import { blindIndexString } from './blindIndex.js';
import { loginOpaque, registerOpaque, resetPasswordOpaque } from './opaque.js';
import { generateAndWrap, openVaultKey, rewrapForMethod } from './vmk.js';
import { newRecoveryPhrase, recoverySecret } from './recovery.js';
import type { PrfProvider } from './passkey.js';
import { open as vaultOpen, seal as vaultSeal, type VaultKey } from './vault.js';
import { fromBase64Std, toBase64Std } from './encoding.js';
import type { Transport } from './transport.js';

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

export interface RecoverySession extends Session {
  /** Re-key auth to a new password. Preserves the vault (the SAME VMK is re-wrapped under the new
   *  export_key — the vault content is never re-encrypted). Single-use: the recovery secret is zeroed
   *  after, so a second call will fail. */
  resetPassword(newPassword: Uint8Array): Promise<void>;
  /** Zero the in-memory recovery secret when finished WITHOUT calling resetPassword. The recovery
   *  secret is retained in this session because the non-extractable VMK cannot itself be re-wrapped, so
   *  resetPassword needs it; if you do not call resetPassword, call dispose() to wipe it. After dispose()
   *  (or resetPassword) the secret is zeroed, and a subsequent resetPassword would fail. */
  dispose(): void;
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
  }): Promise<{ recoveryPhrase: string; session: Session }> {
    const credentialId = blindIndexString(email);
    const { exportKey } = await registerOpaque(this.transport, credentialId, password);
    // Open the try IMMEDIATELY so exportKey is zeroed on ANY subsequent throw. recovEntropy is
    // nullable (derived inside) and zeroed only if it was created — no sentinel.
    let recovEntropy: Uint8Array | undefined;
    try {
      const recoveryPhrase = newRecoveryPhrase();
      recovEntropy = recoverySecret(recoveryPhrase);
      // The WHOLE 64-byte export_key is the 'opaque' wrap secret — do NOT slice it.
      const { vmk, wraps } = await generateAndWrap({ opaque: exportKey, recovery: recovEntropy });
      await this.transport.putWraps({
        credentialId,
        wraps: { opaque: b64(wraps.opaque!), recovery: b64(wraps.recovery!) },
      });
      return { recoveryPhrase, session: sessionFor(vmk, null) };
    } finally {
      exportKey.fill(0);
      recovEntropy?.fill(0);
    }
  }

  /** Migration-only enrolment for an existing SRP account. Same crypto as register(), with two
   *  deliberate differences that make a forced SRP→OPAQUE upgrade safe:
   *   (1) VERIFY-BEFORE-ZERO — it PROVES both the opaque and recovery wraps round-trip while export_key
   *       and the recovery entropy are STILL LIVE. register() zeroes those secrets in its finally before
   *       returning, which makes any post-hoc wrap verification impossible; here the openVaultKey checks
   *       run inside the try, so a bad wrap throws (AES-GCM tag failure) and NOTHING is returned.
   *   (2) NO putWraps — the caller submits the wraps itself, atomically, to /auth/migrate/opaque (so the
   *       auth_version flip and the wrap writes commit in one DB transaction). The wraps are returned as
   *       base64 for that POST. */
  async registerForMigration({
    email,
    password,
  }: {
    email: string;
    password: Uint8Array;
  }): Promise<{ recoveryPhrase: string; session: Session; wraps: { opaque: string; recovery: string } }> {
    const credentialId = blindIndexString(email);
    const { exportKey } = await registerOpaque(this.transport, credentialId, password);
    let recovEntropy: Uint8Array | undefined;
    try {
      const recoveryPhrase = newRecoveryPhrase();
      recovEntropy = recoverySecret(recoveryPhrase);
      // The WHOLE 64-byte export_key is the 'opaque' wrap secret — do NOT slice it.
      const { vmk, wraps } = await generateAndWrap({ opaque: exportKey, recovery: recovEntropy });
      // RECOVERABILITY PROOF — both wraps must decrypt to the real VMK BEFORE the finally zeroes the
      // secrets. A garbled/empty wrap makes openVaultKey throw, aborting the migration with no writes.
      await openVaultKey(wraps.opaque!, exportKey, 'opaque');
      await openVaultKey(wraps.recovery!, recovEntropy, 'recovery');
      return {
        recoveryPhrase,
        session: sessionFor(vmk, null),
        wraps: { opaque: b64(wraps.opaque!), recovery: b64(wraps.recovery!) },
      };
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

  /** Recover via the BIP-39 phrase: unwrap the VMK from the 'recovery' wrap → a Session (no OPAQUE
   *  session key) plus a single-use `resetPassword`. The recovery secret + wrap blob are held in the
   *  returned closure ONLY because the session VMK is non-extractable and cannot itself be re-wrapped;
   *  resetPassword re-derives the raw VMK from the recovery wrap and re-wraps it under the new password,
   *  so the vault is never re-encrypted. The recovery secret is zeroed once resetPassword runs — or, if
   *  the caller never calls resetPassword, once dispose() is called. If NEITHER is called, the 32-byte
   *  recovery secret persists in this session for its lifetime; discard the session promptly. */
  async recoverWithPhrase({
    email,
    phrase,
  }: {
    email: string;
    phrase: string;
  }): Promise<RecoverySession> {
    const credentialId = blindIndexString(email);
    const recovSecret = recoverySecret(phrase); // throws on bad checksum
    const recoveryWrap = await this.transport.getWrap({ credentialId, method: 'recovery' });
    if (!recoveryWrap) throw new Error('tessera: no recovery wrap for this account');
    const recoveryBlob = fromB64(recoveryWrap.blobB64);
    const vmk = await openVaultKey(recoveryBlob, recovSecret, 'recovery'); // throws if phrase is wrong
    const transport = this.transport;
    return {
      ...sessionFor(vmk, /* no OPAQUE session on the recovery path */ null),
      async resetPassword(newPassword: Uint8Array): Promise<void> {
        const { exportKey } = await resetPasswordOpaque(transport, credentialId, newPassword);
        try {
          // Re-wrap the SAME VMK (re-derived from the recovery wrap) under the new export_key.
          const newOpaqueWrap = await rewrapForMethod(
            { blob: recoveryBlob, secret: recovSecret, method: 'recovery' },
            { secret: exportKey, method: 'opaque' },
          );
          await transport.putWraps({ credentialId, wraps: { opaque: b64(newOpaqueWrap) } });
        } finally {
          exportKey.fill(0);
          recovSecret.fill(0);
        }
      },
      dispose(): void {
        // Zero the recovery secret when finished WITHOUT re-keying. Idempotent with the resetPassword
        // wipe; after this, resetPassword would fail (a zeroed secret cannot unwrap the recovery blob).
        recovSecret.fill(0);
      },
    };
  }

  /** Enable passwordless unlock (ADDITIVE). RE-AUTHENTICATES with the password (a non-extractable
   *  session VMK cannot be re-wrapped), then re-wraps the VMK from the 'opaque' wrap into a 'webauthn'
   *  wrap keyed by the PRF output. `prf` runs the WebAuthn create() ceremony (see passkey.evaluatePrf).
   *  Both the export_key and the PRF output are zeroed after use. */
  async enablePasskey({
    email,
    password,
    prf,
  }: {
    email: string;
    password: Uint8Array;
    prf: PrfProvider;
  }): Promise<void> {
    const credentialId = blindIndexString(email);
    const { exportKey } = await loginOpaque(this.transport, credentialId, password); // re-auth
    try {
      const prfOutput = await prf();
      try {
        const opaqueWrap = await this.transport.getWrap({ credentialId, method: 'opaque' });
        if (!opaqueWrap) throw new Error('tessera: no opaque wrap for this account');
        const webauthnWrap = await rewrapForMethod(
          { blob: fromB64(opaqueWrap.blobB64), secret: exportKey, method: 'opaque' },
          { secret: prfOutput, method: 'webauthn' },
        );
        await this.transport.putWraps({ credentialId, wraps: { webauthn: b64(webauthnWrap) } });
      } finally {
        prfOutput.fill(0);
      }
    } finally {
      exportKey.fill(0);
    }
  }

  /** Passwordless unlock via the 'webauthn' wrap. `prf` runs the WebAuthn get() ceremony. No OPAQUE
   *  handshake on this path, so the Session's sessionKeyB64 is null. The PRF output is zeroed after. */
  async unlockWithPasskey({ email, prf }: { email: string; prf: PrfProvider }): Promise<Session> {
    const credentialId = blindIndexString(email);
    const prfOutput = await prf();
    try {
      const wrap = await this.transport.getWrap({ credentialId, method: 'webauthn' });
      if (!wrap) throw new Error('tessera: no passkey wrap for this account');
      const vmk = await openVaultKey(fromB64(wrap.blobB64), prfOutput, 'webauthn');
      return sessionFor(vmk, null); // no OPAQUE session on the passkey path
    } finally {
      prfOutput.fill(0);
    }
  }

  /** Change the password from a logged-in context. Re-authenticates with the OLD
   *  password, runs a fresh OPAQUE registration under the NEW password, and re-wraps
   *  the SAME VMK from the 'opaque' wrap into a new 'opaque' wrap under the new
   *  export_key. The vault is NEVER re-encrypted, and the recovery + passkey wraps
   *  (which wrap the same VMK) stay valid. Both export_keys are zeroed after use. */
  async changePassword({
    email,
    oldPassword,
    newPassword,
  }: {
    email: string;
    oldPassword: Uint8Array;
    newPassword: Uint8Array;
  }): Promise<void> {
    const credentialId = blindIndexString(email);
    const { exportKey: oldExport } = await loginOpaque(this.transport, credentialId, oldPassword); // re-auth
    try {
      const opaqueWrap = await this.transport.getWrap({ credentialId, method: 'opaque' });
      if (!opaqueWrap) throw new Error('tessera: no opaque wrap for this account');
      const { exportKey: newExport } = await resetPasswordOpaque(this.transport, credentialId, newPassword);
      try {
        const newOpaqueWrap = await rewrapForMethod(
          { blob: fromB64(opaqueWrap.blobB64), secret: oldExport, method: 'opaque' },
          { secret: newExport, method: 'opaque' },
        );
        await this.transport.putWraps({ credentialId, wraps: { opaque: b64(newOpaqueWrap) } });
      } finally {
        newExport.fill(0);
      }
    } finally {
      oldExport.fill(0);
    }
  }

  /** Rotate the recovery phrase from a logged-in context. Re-authenticates with the
   *  password, mints a fresh 24-word phrase, and re-wraps the SAME VMK from the
   *  'opaque' wrap into a new 'recovery' wrap under the new phrase's secret. The vault
   *  is never re-encrypted, and the OLD phrase's wrap is overwritten. Returns the new
   *  phrase to show ONCE. export_key and recovery entropy are zeroed after use. */
  async regenerateRecovery({
    email,
    password,
  }: {
    email: string;
    password: Uint8Array;
  }): Promise<{ recoveryPhrase: string }> {
    const credentialId = blindIndexString(email);
    const { exportKey } = await loginOpaque(this.transport, credentialId, password);
    let recovEntropy: Uint8Array | undefined;
    try {
      const opaqueWrap = await this.transport.getWrap({ credentialId, method: 'opaque' });
      if (!opaqueWrap) throw new Error('tessera: no opaque wrap for this account');
      const recoveryPhrase = newRecoveryPhrase();
      recovEntropy = recoverySecret(recoveryPhrase);
      const newRecoveryWrap = await rewrapForMethod(
        { blob: fromB64(opaqueWrap.blobB64), secret: exportKey, method: 'opaque' },
        { secret: recovEntropy, method: 'recovery' },
      );
      await this.transport.putWraps({ credentialId, wraps: { recovery: b64(newRecoveryWrap) } });
      return { recoveryPhrase };
    } finally {
      exportKey.fill(0);
      recovEntropy?.fill(0);
    }
  }
}

/** @internal Exposed for the recovery/passkey methods added in later tasks (not re-exported from index). */
export { sessionFor };

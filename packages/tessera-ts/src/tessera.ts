// High-level Tessera SDK. Orchestrates blind index → OPAQUE → VMK → vault, transport-agnostic. The
// 64-byte OPAQUE export_key and the 32-byte recovery entropy are used ONLY to wrap the VMK, then zeroed
// — they never persist and never cross the wire. The VMK is held as a non-extractable CryptoKey inside
// the returned Session; the raw VMK never leaves WASM/JS linear memory at rest.
import { blindIndexString } from './blindIndex.js';
import {
  loginOpaque,
  registerOpaque,
  resetPasswordOpaque,
  recoveryLoginOpaque,
  registerRecoveryIdentity,
} from './opaque.js';
import { generateAndWrap, openVaultKey, rewrapForMethod } from './vmk.js';
import { newRecoveryPhrase, recoverySecret, recoveryPhrasePassword } from './recovery.js';
import type { PrfProvider } from './passkey.js';
import { open as vaultOpen, seal as vaultSeal, type VaultKey } from './vault.js';
import { fromBase64Std, toBase64Std } from './encoding.js';
import { createRegistrationHandle } from './wasm.js';
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

  /**
   * 🔴 `recoverWithPhrase` WAS REMOVED IN 0.2.0. Use `recoverWithRecoveryIdentity`.
   *
   * The old method derived the recovery secret from the phrase LOCALLY and unwrapped the VMK in the
   * browser. The server never saw the phrase and therefore never verified it — which meant it could
   * not rate-limit guessing, and had to hand the recovery wrap to whoever asked. That is the design
   * the 08-08-2026 audit condemned, and it does not ship in a public Apache-2.0 package.
   *
   * The replacement runs a real OPAQUE ceremony against a SECOND identity on the account. The server
   * verifies the phrase, throttles attempts, and releases the vault and the wrap only afterwards.
   */

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
  /**
   * Recover with the phrase, via the account's RECOVERY OPAQUE identity.
   *
   * Replaces `recoverWithPhrase`. The difference is not cosmetic: the server now runs an OPAQUE
   * ceremony against a second record, so it VERIFIES the phrase, can throttle guesses, and releases
   * the encrypted vault and the recovery wrap only after that ceremony succeeds. The old method
   * proved nothing to anyone and required the wrap to be readable by whoever asked.
   *
   * 🔑 Two secrets, both from the same phrase, deliberately kept apart:
   *   - `recoveryPhrasePassword(phrase)` authenticates — it goes into OPAQUE.
   *   - `recoverySecret(phrase)` (the BIP-39 entropy) decrypts — it opens the `recovery` wrap.
   * Reusing one for both would put the wrap secret through the ceremony and couple them.
   *
   * The returned `resetToken` is what `POST /auth/recovery/opaque/reset` requires; it is the
   * server's evidence that this caller proved possession, and it is single-use.
   */
  async recoverWithRecoveryIdentity({
    email,
    phrase,
  }: {
    email: string;
    phrase: string;
  }): Promise<RecoverySession & { resetToken: string; encryptedVaultB64: string }> {
    const blindIndex = blindIndexString(email);
    const phrasePassword = recoveryPhrasePassword(phrase); // throws on a bad checksum
    let entropy: Uint8Array | undefined;
    let exportKey: Uint8Array | undefined;
    try {
      const res = await recoveryLoginOpaque(this.transport, blindIndex, phrasePassword);
      exportKey = res.exportKey;
      if (!res.recoveryWrappedKeyB64) {
        // The server proved the phrase but holds no wrap for it. That is the half-written state
        // ciphera-id#68 made unrepresentable going forward; say so plainly rather than throwing a
        // decryption error the user would read as "wrong phrase".
        throw new Error('tessera: this account has a recovery identity but no recovery wrap');
      }
      entropy = recoverySecret(phrase);
      const recoveryBlob = fromB64(res.recoveryWrappedKeyB64);
      const vmk = await openVaultKey(recoveryBlob, entropy, 'recovery');

      // Retained for resetPassword ONLY, and zeroed by it or by dispose(). The session VMK is a
      // non-extractable CryptoKey and cannot be re-wrapped, so the reset has to re-derive the raw
      // key from this blob — the same reason the old API held it, on a mechanism that now has the
      // server's verification in front of it.
      const heldEntropy = entropy;
      entropy = undefined; // ownership moves into the closures below
      const transport = this.transport;
      const { resetToken, encryptedVaultB64 } = res;

      return {
        // No OPAQUE session key on this path: recovery proves the phrase, not a login.
        ...sessionFor(vmk, null),
        resetToken,
        encryptedVaultB64,
        async resetPassword(newPassword: Uint8Array): Promise<void> {
          const reg = createRegistrationHandle(newPassword);
          try {
            const { responseB64 } = await transport.registerStart({
              requestB64: toBase64Std(reg.request),
              credentialId: blindIndex,
            });
            const fin = reg.finish(newPassword, fromBase64Std(responseB64));
            try {
              // Re-wrap the SAME VMK under the new export_key. The vault is never re-encrypted.
              const newOpaqueWrap = await rewrapForMethod(
                { blob: recoveryBlob, secret: heldEntropy, method: 'recovery' },
                { secret: fin.exportKey, method: 'opaque' },
              );
              // 🔴 BOTH wraps travel. Sending only the opaque one would leave the account with a
              // recovery record whose wrap the server no longer holds — the exact half-written
              // state ciphera-id#68 exists to prevent, arrived at from the other side.
              await transport.recoveryResetPassword({
                resetToken,
                blindIndex,
                encryptedVaultB64,
                opaqueWrappedKeyB64: b64(newOpaqueWrap),
                registrationUploadB64: toBase64Std(fin.upload),
                credentialIdB64: blindIndex,
                recoveryWrappedKeyB64: b64(recoveryBlob),
              });
            } finally {
              fin.free();
            }
          } finally {
            reg.free();
            heldEntropy.fill(0);
          }
        },
        dispose(): void {
          heldEntropy.fill(0);
        },
      };
    } finally {
      phrasePassword.fill(0);
      entropy?.fill(0);
      exportKey?.fill(0);
    }
  }

  /**
   * Enrol (or ROTATE) the account's recovery identity.
   *
   * Mints a fresh phrase, registers it as a second OPAQUE identity, and re-wraps the SAME VMK under
   * its entropy — then sends the record and the wrap in ONE request, because an account holding one
   * without the other passes recovery login and cannot decrypt.
   *
   * Requires the password: the VMK is non-extractable from a session, so it has to be re-derived
   * from a live ceremony. `reauthToken` is a fresh proof for purpose `enr` — replacing this record
   * installs a permanent second way into the account, so a stolen session must not be enough.
   *
   * Returns the new phrase. Show it ONCE; it cannot be recovered from the server, which is the
   * point.
   */
  async enrolRecoveryIdentity({
    email,
    password,
    reauthToken,
  }: {
    email: string;
    password: Uint8Array;
    reauthToken: string;
  }): Promise<{ recoveryPhrase: string }> {
    const credentialId = blindIndexString(email);
    const { exportKey } = await loginOpaque(this.transport, credentialId, password);
    let entropy: Uint8Array | undefined;
    let phrasePassword: Uint8Array | undefined;
    try {
      const opaqueWrap = await this.transport.getWrap({ credentialId, method: 'opaque' });
      if (!opaqueWrap) throw new Error('tessera: no opaque wrap for this account');

      const recoveryPhrase = newRecoveryPhrase();
      entropy = recoverySecret(recoveryPhrase);
      phrasePassword = recoveryPhrasePassword(recoveryPhrase);

      // Re-wrap the SAME VMK. The vault is never re-encrypted.
      const recoveryWrap = await rewrapForMethod(
        { blob: fromB64(opaqueWrap.blobB64), secret: exportKey, method: 'opaque' },
        { secret: entropy, method: 'recovery' },
      );
      const { uploadB64 } = await registerRecoveryIdentity(
        this.transport,
        credentialId,
        phrasePassword,
      );

      // One call: record + wrap, or neither.
      await this.transport.enrolRecoveryIdentity({
        uploadB64,
        credentialIdB64: credentialId,
        recoveryWrappedKeyB64: b64(recoveryWrap),
        reauthToken,
      });
      return { recoveryPhrase };
    } finally {
      exportKey.fill(0);
      entropy?.fill(0);
      phrasePassword?.fill(0);
    }
  }

  /**
   * 🔴 `regenerateRecovery` WAS REMOVED IN 0.2.0. Use `enrolRecoveryIdentity`, which is the same
   * rotation done safely.
   *
   * It rotated the phrase by writing the new `recovery` WRAP and nothing else — it never touched
   * the recovery OPAQUE record. On an account that has enrolled, that leaves the record
   * authenticating the OLD phrase while the wrap is sealed under the NEW one:
   *
   *   - the old phrase passes the ceremony and then cannot decrypt;
   *   - the new phrase fails the ceremony outright.
   *
   * Recovery is dead, with no error at rotation time and no symptom until the day it is needed.
   * That is the identical half-written state `ciphera-id#68` made unrepresentable on the server,
   * arrived at from the client side — so the method that produces it does not survive either.
   *
   * `enrolRecoveryIdentity` mints the phrase, registers the record AND re-wraps the VMK, and sends
   * both to the server in one request that writes them in a single statement.
   */
}

/** @internal Exposed for the recovery/passkey methods added in later tasks (not re-exported from index). */
export { sessionFor };

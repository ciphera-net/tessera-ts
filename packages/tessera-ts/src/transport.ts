// The relay contract. Tessera is transport-agnostic: the application supplies a `Transport` that
// relays OPAQUE blobs and VMK-wrap storage to its own backend (which fronts tessera-go → the sidecar).
// All OPAQUE blobs are base64-STANDARD strings. `passwordFile` is nullable (string | null) — NEVER a
// sentinel: an unknown account is `null`, mirroring the sidecar's `Option<String>` (the server-side
// user-enumeration safety lives there; the browser cannot distinguish existing from non-existing).
export interface Transport {
  registerStart(req: { requestB64: string; credentialId: string }): Promise<{ responseB64: string }>;

  // The server stores the OPAQUE password file keyed by credentialId; it is NOT returned to the
  // browser (it never leaves the server) — hence `void`, mirroring the Go relay where RegisterFinish
  // hands the password file to the server handler, never back to the client.
  registerFinish(req: { credentialId: string; uploadB64: string }): Promise<void>;

  // The server looks up the stored password file for credentialId (or passes null to the sidecar for
  // an unknown account → timing-safe dummy). Always resolves to {loginId, responseB64}; the browser
  // CANNOT tell an existing from a non-existing account.
  loginStart(req: {
    requestB64: string;
    credentialId: string;
  }): Promise<{ loginId: string; responseB64: string }>;

  loginFinish(req: { loginId: string; finalizationB64: string }): Promise<{ sessionKeyB64: string }>;

  // Replace an existing account's password file after a recovery-driven password reset. Re-keys AUTH
  // only — the vault content is untouched because the same VMK is re-wrapped under the new export_key.
  replacePasswordFile(req: { credentialId: string; uploadB64: string }): Promise<void>;

  // VMK-wrap blob storage (opaque to the server), keyed by credentialId + method.
  putWraps(req: { credentialId: string; wraps: Record<string, string> }): Promise<void>;
  getWrap(req: { credentialId: string; method: string }): Promise<{ blobB64: string } | null>;

  // ---------------------------------------------------------------------------------------------
  // The RECOVERY identity — a SECOND OPAQUE record on the same account, authenticated by the
  // recovery phrase instead of the password.
  //
  // 🔴 It is a separate pair of endpoints, not the same ones with a flag, because the server must
  // never confuse the two records: the recovery record is a permanent, password-independent way in.
  // Ciphera maps these to POST /auth/recovery/opaque/login/{start,finish} and
  // PUT /auth/user/recovery-opaque.
  // ---------------------------------------------------------------------------------------------

  /** First OPAQUE message against the account's RECOVERY record.
   *
   *  Like `loginStart`, this MUST always resolve for a well-formed request — an unknown account
   *  gets a timing-safe dummy — or it becomes an account-existence oracle for anyone who can guess
   *  an email. */
  recoveryLoginStart(req: {
    blindIndex: string;
    requestB64: string;
  }): Promise<{ loginId: string; responseB64: string }>;

  /** Second OPAQUE message. The vault and the recovery wrap come back ONLY here, AFTER the ceremony
   *  has proved possession of the phrase — they used to be handed to any unauthenticated caller,
   *  which is what made the old endpoint a disclosure as well as an oracle. */
  recoveryLoginFinish(req: {
    loginId: string;
    finalizationB64: string;
  }): Promise<{
    resetToken: string;
    encryptedVaultB64: string;
    recoveryWrappedKeyB64: string;
  }>;

  /** Register (or REPLACE) the recovery identity, together with the VMK wrap sealed under the same
   *  phrase.
   *
   *  🔴 BOTH IN ONE CALL, deliberately. The record is what the phrase authenticates against and the
   *  wrap is the vault key sealed under it; an account holding one without a matching other passes
   *  recovery login and then cannot decrypt. The server writes them in a single UPDATE for the same
   *  reason (ciphera-id#68).
   *
   *  `reauthToken` is a fresh password proof — replacing this record installs a permanent second
   *  credential, so a live session alone must not be enough. */
  enrolRecoveryIdentity(req: {
    uploadB64: string;
    credentialIdB64: string;
    recoveryWrappedKeyB64: string;
    reauthToken: string;
  }): Promise<void>;

  /** Set a new password after a recovery ceremony, in ONE server-side transaction.
   *
   *  `resetToken` is the entire authorisation — it is minted only by a completed recovery login and
   *  is single-use. Everything else is the re-registered account: a new OPAQUE record, the vault
   *  re-sealed, and BOTH wraps carried forward so the account is not left holding one without the
   *  other. */
  recoveryResetPassword(req: {
    resetToken: string;
    blindIndex: string;
    encryptedVaultB64: string;
    opaqueWrappedKeyB64: string;
    registrationUploadB64: string;
    credentialIdB64: string;
    recoveryWrappedKeyB64: string;
  }): Promise<void>;
}

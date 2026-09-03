// OPAQUE register/login orchestration over a Transport. Pure relay logic: the crypto is in the WASM
// handles, the wire encoding is base64-STANDARD (NOT the blind-index base64url) end-to-end, and the
// transport carries blobs to the app's backend (→ tessera-go → sidecar). The 64-byte export_key is
// CLIENT-ONLY — the caller (tessera.ts) wraps the VMK under it immediately and then zeroes it. The
// WASM Finish handles are freed once their bytes are consumed (zeroizes the in-WASM key copies).
import { fromBase64Std, toBase64Std } from './encoding.js';
import { createRegistrationHandle, createLoginHandle } from './wasm.js';
import type { Transport } from './transport.js';

/** Drive OPAQUE registration. Returns the 64-byte export_key (CLIENT-ONLY). The server stores the
 *  password file (void). */
export async function registerOpaque(
  t: Transport,
  credentialId: string,
  password: Uint8Array,
): Promise<{ exportKey: Uint8Array }> {
  const reg = createRegistrationHandle(password);
  try {
    const { responseB64 } = await t.registerStart({ requestB64: toBase64Std(reg.request), credentialId });
    const fin = reg.finish(password, fromBase64Std(responseB64));
    try {
      const uploadB64 = toBase64Std(fin.upload);
      const exportKey = fin.exportKey; // getter returns a fresh JS copy; caller owns/zeroes it
      await t.registerFinish({ credentialId, uploadB64 });
      return { exportKey };
    } finally {
      fin.free(); // zeroize the in-WASM export_key copy
    }
  } finally {
    reg.free();
  }
}

/** Drive OPAQUE login. Returns the export_key (CLIENT-ONLY) and the server's session key (base64). */
export async function loginOpaque(
  t: Transport,
  credentialId: string,
  password: Uint8Array,
): Promise<{ exportKey: Uint8Array; sessionKeyB64: string }> {
  const lh = createLoginHandle(password);
  try {
    const { loginId, responseB64 } = await t.loginStart({ requestB64: toBase64Std(lh.request), credentialId });
    const lf = lh.finish(password, fromBase64Std(responseB64));
    try {
      const finalizationB64 = toBase64Std(lf.finalization);
      const exportKey = lf.exportKey;
      const { sessionKeyB64 } = await t.loginFinish({ loginId, finalizationB64 });
      return { exportKey, sessionKeyB64 };
    } finally {
      lf.free(); // zeroize the in-WASM export_key + session_key copies
    }
  } finally {
    lh.free();
  }
}

/** Re-run registration under an EXISTING credentialId to replace the password file (post-recovery
 *  reset). Returns the new export_key so the caller can re-wrap the (preserved) VMK under it. */
export async function resetPasswordOpaque(
  t: Transport,
  credentialId: string,
  newPassword: Uint8Array,
): Promise<{ exportKey: Uint8Array }> {
  const reg = createRegistrationHandle(newPassword);
  try {
    const { responseB64 } = await t.registerStart({ requestB64: toBase64Std(reg.request), credentialId });
    const fin = reg.finish(newPassword, fromBase64Std(responseB64));
    try {
      const uploadB64 = toBase64Std(fin.upload);
      const exportKey = fin.exportKey;
      await t.replacePasswordFile({ credentialId, uploadB64 });
      return { exportKey };
    } finally {
      fin.free();
    }
  } finally {
    reg.free();
  }
}

/**
 * Drive OPAQUE login against the account's RECOVERY record.
 *
 * Structurally identical to `loginOpaque` — same handles, same wire encoding — but pointed at the
 * recovery endpoints, because the two records must never be confused by the server. The password
 * here is `recoveryPhrasePassword(phrase)`, NOT the account password and NOT the phrase entropy.
 *
 * Returns the reset token the server minted, plus the encrypted vault and the recovery wrap, which
 * it releases only now that the ceremony has proved phrase possession.
 *
 * 🔑 The export_key is returned too and the caller owns zeroing it. It is NOT what opens the vault
 * on this path — the `recovery` wrap is sealed under the phrase ENTROPY — but it is real key
 * material and must not be left lying around.
 */
export async function recoveryLoginOpaque(
  t: Transport,
  blindIndex: string,
  phrasePassword: Uint8Array,
): Promise<{
  exportKey: Uint8Array;
  resetToken: string;
  encryptedVaultB64: string;
  recoveryWrappedKeyB64: string;
}> {
  const lh = createLoginHandle(phrasePassword);
  try {
    const { loginId, responseB64 } = await t.recoveryLoginStart({
      requestB64: toBase64Std(lh.request),
      blindIndex,
    });
    const lf = lh.finish(phrasePassword, fromBase64Std(responseB64));
    try {
      const finalizationB64 = toBase64Std(lf.finalization);
      const exportKey = lf.exportKey;
      const res = await t.recoveryLoginFinish({ loginId, finalizationB64 });
      return { exportKey, ...res };
    } finally {
      lf.free();
    }
  } finally {
    lh.free();
  }
}

/**
 * Drive OPAQUE registration for the account's RECOVERY record.
 *
 * Returns the upload the server stores as the recovery password file, and the credential id it is
 * keyed by. The caller pairs these with the VMK wrap in ONE `enrolRecoveryIdentity` call — see the
 * Transport docs for why they may never be written separately.
 *
 * ⚠️ The export_key from this ceremony is deliberately DISCARDED. The `recovery` wrap is sealed
 * under the phrase entropy, not under this key, so keeping it would be key material with no
 * purpose — and a secret with no purpose is a secret waiting to be misused.
 */
export async function registerRecoveryIdentity(
  t: Transport,
  credentialIdB64: string,
  phrasePassword: Uint8Array,
): Promise<{ uploadB64: string }> {
  const reg = createRegistrationHandle(phrasePassword);
  try {
    const { responseB64 } = await t.registerStart({
      requestB64: toBase64Std(reg.request),
      credentialId: credentialIdB64,
    });
    const fin = reg.finish(phrasePassword, fromBase64Std(responseB64));
    try {
      const uploadB64 = toBase64Std(fin.upload);
      fin.exportKey.fill(0); // materialised only to be zeroed; see above
      return { uploadB64 };
    } finally {
      fin.free();
    }
  } finally {
    reg.free();
  }
}

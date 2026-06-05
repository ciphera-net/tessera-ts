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

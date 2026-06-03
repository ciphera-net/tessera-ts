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
}

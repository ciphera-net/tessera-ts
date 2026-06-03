// Base64 + UTF-8 helpers. Browser-safe by design: uses `btoa`/`atob` and `TextEncoder`, never Node's
// `Buffer`, so the same source runs in the browser and (via Node's global btoa/atob) in tests/SSR.
//
// TWO base64 variants, deliberately distinct — mixing them silently breaks the wire:
//   - toBase64Std / fromBase64Std  = standard padded base64 (Rust `BASE64_STANDARD`) for OPAQUE blobs
//     relayed browser ↔ relay ↔ sidecar.
//   - toBase64UrlUnpadded          = base64url WITHOUT padding (Go `base64.RawURLEncoding`) for the
//     blind index / credential_id.

/** Standard padded base64 (`BASE64_STANDARD`) — for OPAQUE wire blobs. */
export function toBase64Std(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromBase64Std(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

/** base64url UNPADDED — for the blind index (matches Go's `base64.RawURLEncoding`).
 *  No decode direction is provided on purpose: blind-index / credential_id values are write-only in
 *  this SDK (sent to the server, never received and decoded here). */
export function toBase64UrlUnpadded(bytes: Uint8Array): string {
  return toBase64Std(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/**
 * Bridge the TS 5.7+ typed-array generic split at the WebCrypto boundary.
 *
 * TS 5.7 split `Uint8Array` into `Uint8Array<ArrayBufferLike>`, but lib.dom's WebCrypto signatures
 * (`BufferSource`) require the `ArrayBuffer`-backed form (`SharedArrayBuffer` is rejected). Every byte
 * value this SDK feeds to WebCrypto is ArrayBuffer-backed at runtime — fresh `new Uint8Array(n)`,
 * `crypto.getRandomValues`, `TextEncoder`, copies out of WASM, and `@scure/bip39` output — and a
 * `Uint8Array` is always a valid `BufferSource` at runtime regardless. This is therefore a sound,
 * zero-copy re-view that closes a TYPE-ONLY gap; use it only when handing bytes to `crypto.subtle`.
 */
export function wcView(b: Uint8Array): Uint8Array<ArrayBuffer> {
  return b as Uint8Array<ArrayBuffer>;
}

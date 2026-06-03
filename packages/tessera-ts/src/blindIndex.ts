// Deterministic, privacy-preserving account lookup key. The normalization (trim → lowercase) and the
// Argon2id derivation live in the WASM core (single source of truth, byte-parity with tessera-go); this
// module only encodes the 32-byte result as base64url-UNPADDED — the form used as the OPAQUE
// credential_id and the server lookup key (matches Go's base64.RawURLEncoding).
import { toBase64UrlUnpadded } from './encoding';
import { blindIndexBytes } from './wasm';

/** base64url-unpadded blind index for `email`. Requires `init()` (WASM) to have resolved. */
export function blindIndexString(email: string): string {
  return toBase64UrlUnpadded(blindIndexBytes(email));
}

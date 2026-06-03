// WebAuthn-PRF passwordless unlock (ADDITIVE — password (OPAQUE) and the recovery phrase are the
// always-available paths; an authenticator without PRF simply cannot enable this, surfaced via
// isPasskeySupported(), never a silent failure).
//
// SEPARATION OF CONCERNS: a WebAuthn ceremony needs app/server context (rpId, challenge, the user's
// credential ids) that this SDK does not own. So the SDK's enable/unlock take a `PrfProvider` — the
// CALLER runs the ceremony (typically via `evaluatePrf` below) and hands back the 32-byte PRF output;
// the SDK wraps/unwraps the VMK under it. The PRF eval salt is the ONE ceremony input the SDK pins
// (it must match between enable and unlock or the derived secret differs).
import { wcView } from './encoding';

/** Fixed PRF eval input — pinned so the PRF output is stable across enable/unlock. */
const PRF_SALT = new TextEncoder().encode('tessera/prf/v1');

/** Supplies the 32-byte WebAuthn-PRF output. The caller runs the ceremony (e.g. via `evaluatePrf`)
 *  with its own RP/challenge/credential context. Returns exactly the bytes used to wrap the VMK.
 *  CONTRACT: the SDK ZEROES the returned buffer after use — return a fresh buffer per call; do not
 *  reuse or share it. */
export type PrfProvider = () => Promise<Uint8Array>;

export interface PrfCreateOptions {
  create: true;
  rpId: string;
  rpName: string;
  userId: Uint8Array;
  userName: string;
  userDisplayName?: string;
  challenge: Uint8Array;
}
export interface PrfGetOptions {
  create: false;
  rpId: string;
  challenge: Uint8Array;
  allowCredentialIds?: Uint8Array[];
}
export type PrfOptions = PrfCreateOptions | PrfGetOptions;

/** Best-effort, NO-user-gesture support probe. Definitive PRF support is only known after a real
 *  get()/create() returns prf results; this is a conservative gate so the UI can OFFER the option.
 *  Never throws (returns false on any failure / when WebAuthn is absent). */
export async function isPasskeySupported(): Promise<boolean> {
  if (!('PublicKeyCredential' in globalThis)) return false;
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

/** Run a WebAuthn ceremony with the PRF extension and return the 32-byte first output. `create`
 *  registers a new credential (enable); otherwise asserts an existing one (unlock). Throws if the
 *  chosen authenticator does not return a PRF result (additive feature — caller surfaces it).
 *  Browser-only; exercised in the Playwright (virtual-authenticator) matrix, not the Node unit tests. */
export async function evaluatePrf(opts: PrfOptions): Promise<Uint8Array> {
  // The PRF extension types are not in every TS lib.dom; cast the extensions object at the boundary.
  // PRF_SALT is already a Uint8Array (a valid BufferSource), so no wcView wrap is needed here.
  const extensions = { prf: { eval: { first: PRF_SALT } } } as AuthenticationExtensionsClientInputs;

  let cred: PublicKeyCredential | null;
  if (opts.create) {
    cred = (await navigator.credentials.create({
      publicKey: {
        challenge: wcView(opts.challenge),
        rp: { id: opts.rpId, name: opts.rpName },
        user: {
          id: wcView(opts.userId),
          name: opts.userName,
          displayName: opts.userDisplayName ?? opts.userName,
        },
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 }, // ES256
          { type: 'public-key', alg: -257 }, // RS256
        ],
        authenticatorSelection: { userVerification: 'required', residentKey: 'required' },
        extensions,
      },
    })) as PublicKeyCredential | null;
  } else {
    cred = (await navigator.credentials.get({
      publicKey: {
        challenge: wcView(opts.challenge),
        rpId: opts.rpId,
        allowCredentials: (opts.allowCredentialIds ?? []).map((id) => ({
          type: 'public-key' as const,
          id: wcView(id),
        })),
        userVerification: 'required',
        extensions,
      },
    })) as PublicKeyCredential | null;
  }

  if (!cred) throw new Error('tessera: WebAuthn ceremony returned no credential');
  const first = (
    cred.getClientExtensionResults() as { prf?: { results?: { first?: ArrayBuffer | ArrayBufferView } } }
  ).prf?.results?.first;
  if (!first) {
    throw new Error('tessera: authenticator did not return a PRF result (PRF unsupported by this authenticator)');
  }
  return first instanceof ArrayBuffer ? new Uint8Array(first) : new Uint8Array(first.buffer, first.byteOffset, first.byteLength);
}

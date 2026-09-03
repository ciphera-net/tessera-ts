// Error taxonomy mirroring tessera-go/vault.go. One GENERIC error for wrong-key / wrong-context /
// tamper / too-short (no decryption oracle — these MUST be indistinguishable), and a DISTINCT error
// for an unrecognized version byte (forward-compat; the version is not secret).

export class UnsupportedVersionError extends Error {
  constructor() {
    super('tessera: unsupported vault envelope version');
    this.name = 'UnsupportedVersionError';
  }
}

export class MalformedEnvelopeError extends Error {
  constructor() {
    super('tessera: malformed or unauthentic vault envelope');
    this.name = 'MalformedEnvelopeError';
  }
}

export class EmptyVaultKeyError extends Error {
  constructor() {
    super('tessera: empty vault key');
    this.name = 'EmptyVaultKeyError';
  }
}

export class EmptyContextError extends Error {
  constructor() {
    super('tessera: empty record context');
    this.name = 'EmptyContextError';
  }
}

/**
 * The password did not open the OPAQUE envelope — i.e. wrong password (or wrong
 * account for this password file).
 *
 * 🔑 In OPAQUE the SERVER cannot tell a right password from a wrong one; only
 * the client can, at `login_finish`, when the envelope fails to open. So this is
 * the canonical wrong-password signal for the whole system, and it is raised
 * here rather than by any HTTP status.
 *
 * ⚠️ Unlike the vault-envelope errors above — which are deliberately
 * indistinguishable because telling them apart would be a decryption oracle —
 * this one is safe to distinguish. It reports the outcome of a password the
 * caller just supplied; it tells an attacker nothing they did not already know
 * by typing it.
 */
export class InvalidCredentialsError extends Error {
  constructor() {
    super('tessera: invalid credentials');
    this.name = 'InvalidCredentialsError';
  }
}

/**
 * The OPAQUE ceremony failed for a reason that is NOT a wrong password —
 * a malformed or tampered server response, a serialization fault, or an
 * internal library error.
 *
 * 🔴 This is deliberately NOT folded into `InvalidCredentialsError`. Reporting a
 * broken ceremony as "wrong password" would send a user to reset a password that
 * was already correct and would hide a real fault behind the one message nobody
 * investigates. A wrong password is expected; this is not.
 *
 * `cause` carries the underlying error for logs. The MESSAGE is fixed and
 * `tessera:`-prefixed so it can never carry WASM internals into a UI.
 */
export class OpaqueProtocolError extends Error {
  constructor(cause?: unknown) {
    super('tessera: OPAQUE ceremony failed');
    this.name = 'OpaqueProtocolError';
    this.cause = cause;
  }
}

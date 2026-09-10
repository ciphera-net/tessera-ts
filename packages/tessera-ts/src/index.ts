// Public API of @ciphera-net/tessera.
export {
  Tessera,
  vaultOpsFor,
  type Session,
  type RecoverySession,
  type VaultOps,
} from './tessera.js';
// The VMK type. A Session now carries the key itself, so a host that wants to
// persist the unlocked state (IndexedDB — a CryptoKey is structured-cloneable,
// a closure is not) can name it. Always non-extractable; see Session.vaultKey.
export type { VaultKey } from './vault.js';
export { init } from './wasm.js';
export { blindIndexString } from './blindIndex.js';
export { newRecoveryPhrase, recoveryPhrasePassword } from './recovery.js';
export {
  isPasskeySupported,
  evaluatePrf,
  type PrfProvider,
  type PrfOptions,
  type PrfCreateOptions,
  type PrfGetOptions,
} from './passkey.js';
export type { Transport } from './transport.js';
export type { UnlockMethod } from './vmk.js';
export {
  UnsupportedVersionError,
  MalformedEnvelopeError,
  EmptyVaultKeyError,
  EmptyContextError,
  InvalidCredentialsError,
  OpaqueProtocolError,
} from './errors.js';

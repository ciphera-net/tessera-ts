// Public API of @ciphera-net/tessera.
export { Tessera, type Session, type RecoverySession } from './tessera.js';
export { init } from './wasm.js';
export { blindIndexString } from './blindIndex.js';
export { newRecoveryPhrase } from './recovery.js';
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
} from './errors.js';

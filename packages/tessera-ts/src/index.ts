// Public API of @ciphera-net/tessera.
export { Tessera, type Session } from './tessera';
export { init } from './wasm';
export { blindIndexString } from './blindIndex';
export { newRecoveryPhrase } from './recovery';
export type { Transport } from './transport';
export type { UnlockMethod } from './vmk';
export {
  UnsupportedVersionError,
  MalformedEnvelopeError,
  EmptyVaultKeyError,
  EmptyContextError,
} from './errors';

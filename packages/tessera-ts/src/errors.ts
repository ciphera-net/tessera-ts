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

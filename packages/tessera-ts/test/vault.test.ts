import { describe, it, expect, beforeAll } from 'vitest';
import { importVaultKey, seal, open, type VaultKey } from '../src/vault';
import {
  EmptyContextError,
  MalformedEnvelopeError,
  UnsupportedVersionError,
} from '../src/errors';

const RAW = Uint8Array.from({ length: 32 }, (_, i) => i); // deterministic 32-byte vault key
let vaultKey: VaultKey;

beforeAll(async () => {
  vaultKey = await importVaultKey(RAW);
});

describe('vault seal/open (byte-compatible with tessera-go vault.go)', () => {
  it('round-trips plaintext under the same context', async () => {
    const pt = new TextEncoder().encode('hello vault');
    const env = await seal(vaultKey, 'address', pt);
    const out = await open(vaultKey, 'address', env);
    expect(out).toEqual(pt);
  });

  it('produces the exact envelope layout 1 + 12 + 48 + 12 + (len+16)', async () => {
    const pt = new TextEncoder().encode('hello world'); // 11 bytes
    const env = await seal(vaultKey, 'address', pt);
    // 1 (version) + 12 (nonceW) + 48 (wrappedDEK) + 12 (nonceC) + 11 + 16 (tag) = 100
    expect(env.length).toBe(1 + 12 + 48 + 12 + (pt.length + 16));
    expect(env[0]).toBe(0x01); // version byte
  });

  it('opening under a DIFFERENT context fails with MalformedEnvelope (key separation)', async () => {
    const env = await seal(vaultKey, 'address', new TextEncoder().encode('secret'));
    await expect(open(vaultKey, 'totp', env)).rejects.toBeInstanceOf(MalformedEnvelopeError);
  });

  it('flipping a ciphertext byte fails with MalformedEnvelope (tamper detection)', async () => {
    const env = await seal(vaultKey, 'address', new TextEncoder().encode('secret payload'));
    env[env.length - 1] ^= 0xff; // corrupt the last ciphertext/tag byte
    await expect(open(vaultKey, 'address', env)).rejects.toBeInstanceOf(MalformedEnvelopeError);
  });

  it('an unrecognized version byte fails with UnsupportedVersion', async () => {
    const env = await seal(vaultKey, 'address', new TextEncoder().encode('x'));
    env[0] = 0x02;
    await expect(open(vaultKey, 'address', env)).rejects.toBeInstanceOf(UnsupportedVersionError);
  });

  it('a too-short (50-byte) envelope with a valid version byte fails with MalformedEnvelope', async () => {
    const tooShort = new Uint8Array(50);
    tooShort[0] = 0x01; // valid version → forces the length guard (not the version guard) to fire
    await expect(open(vaultKey, 'address', tooShort)).rejects.toBeInstanceOf(MalformedEnvelopeError);
  });

  it('an empty context throws EmptyContext on both seal and open', async () => {
    const pt = new TextEncoder().encode('x');
    await expect(seal(vaultKey, '', pt)).rejects.toBeInstanceOf(EmptyContextError);
    const env = await seal(vaultKey, 'address', pt);
    await expect(open(vaultKey, '', env)).rejects.toBeInstanceOf(EmptyContextError);
  });
});

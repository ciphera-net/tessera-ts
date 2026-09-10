import { describe, it, expect, beforeAll } from 'vitest';
import { importVaultKey, type VaultKey } from '../src/vault';
import { vaultOpsFor } from '../src/tessera';

/**
 * A Session now carries the VMK itself, so a host can persist the unlocked
 * state instead of re-running a ceremony on every page load.
 *
 * These tests pin the three properties a host's threat model is allowed to rely
 * on. They are deliberately about the KEY OBJECT rather than about any flow: a
 * host that stores one is trusting exactly these, and nothing in a ceremony
 * test would catch them changing.
 */

const RAW = Uint8Array.from({ length: 32 }, (_, i) => i * 3);
let vaultKey: VaultKey;

beforeAll(async () => {
  vaultKey = await importVaultKey(RAW);
});

describe('the VaultKey a host may persist', () => {
  /**
   * 🔴 THE PROPERTY THE WHOLE DECISION RESTS ON. `extractable: false` means
   * there are no key bytes in JS to read, copy or exfiltrate — a holder gets
   * USE of the key on that device, never a copy of it. If this ever became
   * true, persisting the key would mean persisting exportable key material, and
   * "the key never leaves the device" would stop being true.
   */
  it('is non-extractable, and refuses to be exported', async () => {
    expect(vaultKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('raw', vaultKey)).rejects.toThrow();
  });

  /**
   * 🔑 STRONGER THAN THE FLAG. WebCrypto refuses to import an HKDF key as
   * extractable at all, so this is not merely a value we chose — the platform
   * will not produce the other kind. Found by mutating `importVaultKey` to pass
   * `true`: `importKey` itself throws.
   */
  it('cannot even be created extractable — the platform refuses', async () => {
    await expect(
      crypto.subtle.importKey('raw', RAW, 'HKDF', true, ['deriveKey']),
    ).rejects.toThrow();
  });

  /** It derives, and nothing else — no encrypt/decrypt/sign/wrap usage to abuse. */
  it('carries deriveKey and no other usage', () => {
    expect(vaultKey.usages).toEqual(['deriveKey']);
    expect(vaultKey.algorithm.name).toBe('HKDF');
  });

  /**
   * 🔑 THE REASON THE KEY IS EXPOSED AT ALL. `Session.vault` is a pair of
   * CLOSURES, and functions are not structured-cloneable — a Session simply
   * cannot go into IndexedDB. A CryptoKey can, which is the entire difference
   * between "unlocked for this page" and "unlocked on this device".
   *
   * structuredClone is the same algorithm IndexedDB stores by, so this is the
   * real check rather than a stand-in for it.
   */
  it('survives structuredClone — which a Session, being closures, does not', () => {
    expect(() => structuredClone(vaultKey)).not.toThrow();
    const ops = vaultOpsFor(vaultKey);
    expect(() => structuredClone(ops)).toThrow();
  });

  it('is still non-extractable after a round trip through structuredClone', async () => {
    const restored = structuredClone(vaultKey) as VaultKey;
    expect(restored.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('raw', restored)).rejects.toThrow();
  });
});

describe('vaultOpsFor', () => {
  it('rebuilds ops that open what the original sealed', async () => {
    const pt = new TextEncoder().encode('restored after a reload');
    const sealed = await vaultOpsFor(vaultKey).seal('vault', pt);

    // The host's real sequence: persist the key, get it back, rebuild the ops.
    const restored = structuredClone(vaultKey) as VaultKey;
    const out = await vaultOpsFor(restored).open('vault', sealed);
    expect(out).toEqual(pt);
  });

  /**
   * The context is part of the AAD and the KEK derivation, so a rebuilt pair
   * must be as strict about it as the original. A host that persisted a key and
   * silently opened a foreign context would be the failure this guards.
   */
  it('is still bound to the context', async () => {
    const sealed = await vaultOpsFor(vaultKey).seal('vault', new Uint8Array([1, 2, 3]));
    await expect(vaultOpsFor(vaultKey).open('other', sealed)).rejects.toThrow();
  });

  it('refuses an empty context, exactly as seal/open do', async () => {
    await expect(vaultOpsFor(vaultKey).seal('', new Uint8Array([1]))).rejects.toThrow();
  });
});

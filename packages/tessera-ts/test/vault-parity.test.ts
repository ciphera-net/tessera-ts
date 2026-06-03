import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { importVaultKey, seal, open } from '../src/vault';

// Cross-language Open-parity with tessera-go. Encrypt is non-deterministic (random nonce + DEK), so we
// do NOT assert envelope byte-equality — we assert that each side can OPEN the other's envelope and
// recover the exact plaintext. That is the property that matters for interop. The prime suspects if
// this fails are the HKDF salt (must be 32 zero bytes both sides) and the AAD bytes.
const here = dirname(fileURLToPath(import.meta.url));
const HARNESS_DIR = join(here, '..', '..', '..', 'harness', 'vault-parity'); // tessera-ts/harness/vault-parity

const toHex = (u8: Uint8Array) => Buffer.from(u8).toString('hex');
const fromHex = (h: string) => new Uint8Array(Buffer.from(h, 'hex'));

// Invoke the Go helper: `go run . <seal|open> <vaultKeyHex> <context> <dataHex>` → prints result hex.
function goVault(mode: 'seal' | 'open', keyHex: string, context: string, dataHex: string): string {
  return execFileSync('go', ['run', '.', mode, keyHex, context, dataHex], {
    cwd: HARNESS_DIR,
    encoding: 'utf8',
  }).trim();
}

const KEY = new Uint8Array(32).fill(0xab); // fixed, deterministic 32-byte vault key
const KEY_HEX = toHex(KEY);
const CONTEXT = 'address';

describe('vault cross-language Open-parity (TS ↔ tessera-go)', () => {
  it(
    'TS-seal → Go-open recovers the plaintext',
    async () => {
      const vaultKey = await importVaultKey(KEY);
      const pt = new TextEncoder().encode('cross-language secret');
      const env = await seal(vaultKey, CONTEXT, pt);
      const goPtHex = goVault('open', KEY_HEX, CONTEXT, toHex(env));
      expect(goPtHex).toBe(toHex(pt));
    },
    30_000, // `go run` compiles on first call
  );

  it(
    'Go-seal → TS-open recovers the plaintext',
    async () => {
      const vaultKey = await importVaultKey(KEY);
      const pt = new TextEncoder().encode('the other direction');
      const goEnvHex = goVault('seal', KEY_HEX, CONTEXT, toHex(pt));
      const out = await open(vaultKey, CONTEXT, fromHex(goEnvHex));
      expect(out).toEqual(pt);
    },
    30_000,
  );

  it(
    'a TS envelope opened by Go under the WRONG context fails (key separation holds cross-language)',
    async () => {
      const vaultKey = await importVaultKey(KEY);
      const env = await seal(vaultKey, CONTEXT, new TextEncoder().encode('secret'));
      // Go's Open under a different context must fail (non-zero exit → execFileSync throws).
      expect(() => goVault('open', KEY_HEX, 'totp', toHex(env))).toThrow();
    },
    30_000,
  );
});

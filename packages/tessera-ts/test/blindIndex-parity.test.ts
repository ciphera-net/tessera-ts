import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { init } from '../src/wasm';
import { blindIndexString } from '../src/blindIndex';

// Byte-exact cross-language parity: the WASM blind index (Rust argon2, normalize trim→lower) must equal
// tessera-go's BlindIndexString for the same email. Unlike the vault (random nonce), the blind index is
// deterministic, so this is an exact string-equality check. This is also the first test to exercise the
// wasm.ts isomorphic loader in Node.
const here = dirname(fileURLToPath(import.meta.url));
const HARNESS_DIR = join(here, '..', '..', '..', 'harness', 'blindindex-parity');

function goBlindIndex(email: string): string {
  return execFileSync('go', ['run', '.', email], { cwd: HARNESS_DIR, encoding: 'utf8' }).trim();
}

beforeAll(async () => {
  await init();
});

describe('blind index cross-language parity (TS WASM ↔ tessera-go)', () => {
  const emails = ['user@example.com', 'Alice@Example.ORG', 'bob+tag@gmail.com'];
  for (const email of emails) {
    it(
      `matches Go BlindIndexString for "${email}"`,
      () => {
        expect(blindIndexString(email)).toBe(goBlindIndex(email));
      },
      30_000, // `go run` compiles on first call; WASM Argon2id(64MiB) per call
    );
  }

  it(
    'normalizes "  User@Example.com " to the SAME index as Go for the canonical form (cross-language trim+lower)',
    () => {
      // TS-normalize(messy input) must equal Go-normalize(canonical) — proves the trim→lower contract
      // matches across languages, not just within TS.
      expect(blindIndexString('  User@Example.com ')).toBe(goBlindIndex('user@example.com'));
    },
    30_000,
  );
});

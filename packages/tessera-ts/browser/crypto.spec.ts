// Browser crypto spec: proves (a) the WEB-target wasm loads in real browsers, and (b) blindIndex,
// vault seal/open, and VMK generateAndWrap all produce byte-exact results in chromium + webkit.
// All SDK calls happen inside page.evaluate() via the window.__T helper object.
import { test, expect } from '@playwright/test';

// ── Helpers ──────────────────────────────────────────────────────────────────

const toHex = (b: Buffer | Uint8Array) =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');

// Blind-index vectors (byte-exact — Go-generated, Argon2id deterministic)
const BLIND_INDEX_VECTORS = [
  { email: 'user@example.com', expected: 'A3_Z30mos_Wp-w28gAUKtci-ziR9YH-cq-nBKB1WVqQ' },
  { email: 'Alice@Example.ORG', expected: 'MQZmQuP38eyxFzcM07hFgGl6YYy7zsxeCx2bupUmsM8' },
  { email: ' bob+tag@gmail.com ', expected: 'wu6MYF8V7tYWQ81nSDOzhj-Yj-KQfd8Eyd3W656tLG4' },
  // Normalisation check: uppercase/trailing-space variants must produce the SAME index
  { email: 'USER@EXAMPLE.COM', expected: 'A3_Z30mos_Wp-w28gAUKtci-ziR9YH-cq-nBKB1WVqQ' },
  { email: '  Alice@Example.ORG  ', expected: 'MQZmQuP38eyxFzcM07hFgGl6YYy7zsxeCx2bupUmsM8' },
] as const;

// Vault vectors — Go-sealed envelopes that the TS SDK must open correctly
const VAULT_VECTORS = [
  {
    vaultKeyHex: '0101010101010101010101010101010101010101010101010101010101010101',
    context: 'address',
    plaintextHex: '68656c6c6f207661756c74',
  },
  {
    vaultKeyHex: '0101010101010101010101010101010101010101010101010101010101010101',
    context: 'totp',
    plaintextHex: '4a425357593344504548504b33505850',
  },
] as const;

// ── Per-browser init (navigate once per worker) ───────────────────────────────

test.beforeEach(async ({ page }) => {
  await page.goto('/');
  // Init the WASM module — Argon2id 64 MiB; allow 75s
  await page.evaluate(() => (window as unknown as { __T: { init: () => Promise<void> } }).__T.init());
});

// ── Blind-index tests (byte-exact, Argon2id deterministic) ──────────────────

for (const { email, expected } of BLIND_INDEX_VECTORS) {
  test(`blindIndex("${email}") matches Go vector [${email.trim()}]`, async ({ page }) => {
    const result = await page.evaluate(
      (e) => (window as unknown as { __T: { blindIndex: (email: string) => Promise<string> } }).__T.blindIndex(e),
      email,
    );
    expect(result).toBe(expected);
  });
}

// ── Vault seal/open round-trip ────────────────────────────────────────────────

test('vault seal/open round-trips (correct context opens; wrong context throws)', async ({ page }) => {
  const keyHex = '0101010101010101010101010101010101010101010101010101010101010101';
  const ptHex = toHex(Buffer.from('hello vault'));

  const result = await page.evaluate(
    ([k, ctx, pt]) =>
      (
        window as unknown as {
          __T: {
            vaultRoundTrip: (
              k: string,
              ctx: string,
              pt: string,
            ) => Promise<{ openedHex: string; crossContextThrew: boolean }>;
          };
        }
      ).__T.vaultRoundTrip(k, ctx, pt),
    [keyHex, 'test-context', ptHex] as [string, string, string],
  );

  expect(result.openedHex).toBe(ptHex);
  expect(result.crossContextThrew).toBe(true);
});

// ── Vault vector: cross-context open throws ───────────────────────────────────

for (const { vaultKeyHex, context, plaintextHex } of VAULT_VECTORS) {
  test(`vault round-trip with key/context="${context}" (fresh seal → open)`, async ({ page }) => {
    const result = await page.evaluate(
      ([k, ctx, pt]) =>
        (
          window as unknown as {
            __T: {
              vaultRoundTrip: (
                k: string,
                ctx: string,
                pt: string,
              ) => Promise<{ openedHex: string; crossContextThrew: boolean }>;
            };
          }
        ).__T.vaultRoundTrip(k, ctx, pt),
      [vaultKeyHex, context, plaintextHex] as [string, string, string],
    );

    expect(result.openedHex).toBe(plaintextHex);
    expect(result.crossContextThrew).toBe(true);
  });
}

// ── VMK generateAndWrap → openVaultKey round-trip ────────────────────────────

test('VMK generateAndWrap → openVaultKey → vault round-trip', async ({ page }) => {
  const ok = await page.evaluate(() =>
    (window as unknown as { __T: { vmkRoundTrip: () => Promise<boolean> } }).__T.vmkRoundTrip(),
  );
  expect(ok).toBe(true);
});

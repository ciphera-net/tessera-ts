import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { init } from '../src/wasm';
import { Tessera } from '../src/tessera';
import { utf8 } from '../src/encoding';
import { startSidecarTransport, type SidecarTransport } from './helpers/sidecarTransport';

// regenerateRecovery rotates the BIP-39 phrase from a logged-in context: re-auth,
// mint a fresh phrase, and re-wrap the SAME VMK under the new recovery secret. The
// vault is never re-encrypted; the OLD phrase must stop recovering.
let h: SidecarTransport;

beforeAll(async () => {
  await init();
  h = await startSidecarTransport();
}, 30_000);

afterAll(async () => {
  await h?.stop();
});

describe('Tessera.regenerateRecovery', () => {
  it(
    'rotates the recovery phrase, preserving the vault; the old phrase stops working',
    async () => {
      const sdk = new Tessera(h.transport);
      const email = 'regen-rec@example.com';
      const password = utf8('correct-horse-regen-x');

      const { recoveryPhrase: oldPhrase } = await sdk.register({ email, password });

      const { recoveryPhrase: newPhrase } = await sdk.regenerateRecovery({ email, password });
      expect(newPhrase).not.toBe(oldPhrase);
      expect(newPhrase.split(' ')).toHaveLength(24);

      // The NEW phrase recovers (recovery path runs no OPAQUE handshake → null session key).
      const rec = await sdk.recoverWithPhrase({ email, phrase: newPhrase });
      expect(rec.sessionKeyB64).toBeNull();
      rec.dispose();

      // The OLD phrase no longer recovers (its wrap was replaced).
      await expect(sdk.recoverWithPhrase({ email, phrase: oldPhrase })).rejects.toThrow();
    },
    60_000,
  );
});

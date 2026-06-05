import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { init } from '../src/wasm';
import { Tessera } from '../src/tessera';
import { utf8 } from '../src/encoding';
import { startSidecarTransport, type SidecarTransport } from './helpers/sidecarTransport';

// changePassword is a logged-in re-key: re-auth with the OLD password, register
// under the NEW one, and re-wrap the SAME VMK under the new export_key. The vault
// is never re-encrypted, so a record sealed before the change still opens after.
let h: SidecarTransport;

beforeAll(async () => {
  await init();
  h = await startSidecarTransport();
}, 30_000);

afterAll(async () => {
  await h?.stop();
});

describe('Tessera.changePassword', () => {
  it(
    're-wraps the same VMK under the new password; the old password stops working',
    async () => {
      const sdk = new Tessera(h.transport);
      const email = 'change-pw@example.com';
      const oldPw = utf8('old-correct-horse-battery');
      const newPw = utf8('new-hunter2-staple-x');

      await sdk.register({ email, password: oldPw });
      const before = await sdk.login({ email, password: oldPw });
      const env = await before.vault.seal('vault', utf8('{"email":"change-pw@example.com"}'));

      await sdk.changePassword({ email, oldPassword: oldPw, newPassword: newPw });

      // New password unlocks; the pre-change record still opens → SAME VMK preserved.
      const after = await sdk.login({ email, password: newPw });
      expect(new TextDecoder().decode(await after.vault.open('vault', env))).toContain('change-pw');

      // The old password no longer authenticates.
      await expect(sdk.login({ email, password: oldPw })).rejects.toThrow();
    },
    60_000,
  );
});

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { init } from '../src/wasm';
import { Tessera } from '../src/tessera';
import { newRecoveryPhrase } from '../src/recovery';
import { MalformedEnvelopeError } from '../src/errors';
import { utf8 } from '../src/encoding';
import { startSidecarTransport, type SidecarTransport } from './helpers/sidecarTransport';

// Recovery + password-reset flow over a REAL sidecar. Requires TESSERA_SIDECAR_BIN.
let h: SidecarTransport;

beforeAll(async () => {
  await init();
  h = await startSidecarTransport();
}, 30_000);

afterAll(async () => {
  await h?.stop();
});

describe('Tessera recovery + password reset', () => {
  it(
    'recover → resetPassword → new password opens a PRE-RESET record (the VMK survives the reset)',
    async () => {
      const tessera = new Tessera(h.transport);
      const email = 'recover-reset@example.com';
      const oldPw = utf8('old-password-123');
      const { recoveryPhrase } = await tessera.register({ email, password: oldPw });

      // Seal a record under the original VMK via a normal login session.
      const s1 = await tessera.login({ email, password: oldPw });
      const secret = utf8('survives the reset');
      const env = await s1.vault.seal('address', secret);

      // Recover via phrase: no OPAQUE session, but the SAME VMK opens the record.
      const rec = await tessera.recoverWithPhrase({ email, phrase: recoveryPhrase });
      expect(rec.sessionKeyB64).toBeNull();
      expect(await rec.vault.open('address', env)).toEqual(secret);

      // Reset the password — vault content is NOT re-encrypted.
      const newPw = utf8('brand-new-password');
      await rec.resetPassword(newPw);

      // New password logs in and opens the pre-reset record; the old password no longer works.
      const s2 = await tessera.login({ email, password: newPw });
      expect(await s2.vault.open('address', env)).toEqual(secret);
      await expect(tessera.login({ email, password: oldPw })).rejects.toThrow();
    },
    60_000,
  );

  it(
    'recoverWithPhrase with a different (valid but wrong) phrase is rejected',
    async () => {
      const tessera = new Tessera(h.transport);
      const email = 'recover-wrongphrase@example.com';
      await tessera.register({ email, password: utf8('pw') });
      const wrongPhrase = newRecoveryPhrase(); // valid checksum, different entropy → wrong recovery wrap
      await expect(
        tessera.recoverWithPhrase({ email, phrase: wrongPhrase }),
      ).rejects.toBeInstanceOf(MalformedEnvelopeError);
    },
    40_000,
  );
});

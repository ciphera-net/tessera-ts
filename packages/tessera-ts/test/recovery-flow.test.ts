import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { init } from '../src/wasm';
import { Tessera } from '../src/tessera';
import { newRecoveryPhrase } from '../src/recovery';
import { utf8 } from '../src/encoding';
import { startSidecarTransport, type SidecarTransport } from './helpers/sidecarTransport';

/**
 * Recovery over a REAL sidecar, through the RECOVERY OPAQUE IDENTITY (0.2.0).
 *
 * 🔴 These tests were rewritten wholesale, not adapted. The old ones drove
 * `recoverWithPhrase`, which derived the recovery secret locally and unwrapped the VMK in the
 * browser — the server never saw the phrase, so it could not verify it, could not rate-limit
 * guessing, and had to hand the wrap to whoever asked. That is the design the 08-08-2026 audit
 * condemned and it is gone.
 *
 * What replaces it is a real OPAQUE ceremony against a SECOND identity on the account. The
 * difference these tests must actually pin is that the SERVER now decides: it verifies the phrase
 * and releases the vault and the wrap only afterwards.
 *
 * Requires TESSERA_SIDECAR_BIN.
 */
let h: SidecarTransport;

beforeAll(async () => {
  await init();
  h = await startSidecarTransport();
}, 30_000);

afterAll(async () => {
  await h?.stop();
});

/** Register an account and enrol its recovery identity. Returns the enrolled phrase. */
async function enrolled(tessera: Tessera, email: string, password: Uint8Array) {
  await tessera.register({ email, password });
  // The `enr` proof is the server's business; the double does not check it, and a test that
  // asserted on a value it also supplies would be asserting on itself.
  const { recoveryPhrase } = await tessera.enrolRecoveryIdentity({
    email,
    password,
    reauthToken: 'enr-token',
  });
  return recoveryPhrase;
}

describe('Tessera recovery via the recovery identity', () => {
  it(
    'enrol → recover → the SAME VMK opens a record sealed before recovery',
    async () => {
      const tessera = new Tessera(h.transport);
      const email = 'recover-identity@example.com';
      const pw = utf8('old-password-123');
      const phrase = await enrolled(tessera, email, pw);

      // Seal something under the original VMK via a normal login.
      const s1 = await tessera.login({ email, password: pw });
      const secret = utf8('survives recovery');
      const env = await s1.vault.seal('address', secret);

      const rec = await tessera.recoverWithRecoveryIdentity({ email, phrase });

      // Recovery is not a login: there is no OPAQUE session key.
      expect(rec.sessionKeyB64).toBeNull();
      // The server minted a reset token only because the ceremony succeeded.
      expect(rec.resetToken).toBeTruthy();
      // And the same VMK opens the pre-recovery record.
      expect(await rec.vault.open('address', env)).toEqual(secret);

      rec.dispose();
    },
    60_000,
  );

  it(
    'recover → resetPassword → the new password opens a PRE-RESET record',
    async () => {
      const tessera = new Tessera(h.transport);
      const email = 'recover-reset@example.com';
      const oldPw = utf8('old-password-123');
      const phrase = await enrolled(tessera, email, oldPw);

      const s1 = await tessera.login({ email, password: oldPw });
      const secret = utf8('survives the reset');
      const env = await s1.vault.seal('address', secret);

      const rec = await tessera.recoverWithRecoveryIdentity({ email, phrase });
      const newPw = utf8('brand-new-password');
      await rec.resetPassword(newPw);

      // The vault content was never re-encrypted: the same envelope still opens.
      const s2 = await tessera.login({ email, password: newPw });
      expect(await s2.vault.open('address', env)).toEqual(secret);
      await expect(tessera.login({ email, password: oldPw })).rejects.toThrow();

      // 🔴 THE RESET MUST CARRY THE RECOVERY WRAP FORWARD. The reset re-registers the PASSWORD
      // identity; it does not touch the recovery record, so that record still authenticates this
      // same phrase. If the reset dropped the wrap, the account would keep a recovery record with
      // nothing to decrypt — passing the ceremony and then failing, which is the half-written state
      // this whole change exists to make unreachable. Caught by mutation: sending an empty
      // recovery_wrapped_key on reset left every other assertion here green.
      const again = await tessera.recoverWithRecoveryIdentity({ email, phrase });
      expect(await again.vault.open('address', env)).toEqual(secret);
      again.dispose();
    },
    60_000,
  );

  it(
    'a valid but WRONG phrase is refused by the server ceremony, not by local decryption',
    async () => {
      const tessera = new Tessera(h.transport);
      const email = 'recover-wrongphrase@example.com';
      const pw = utf8('pw');
      await enrolled(tessera, email, pw);

      // Correct checksum, different entropy — so it is a well-formed phrase for the WRONG account.
      const wrongPhrase = newRecoveryPhrase();

      // 🔑 THE POINT OF THE WHOLE CHANGE. Under the old design this failed at local decryption,
      // AFTER the server had already handed over the wrap — which is what made phrase guessing
      // unthrottleable. It must now fail in the OPAQUE ceremony instead, before anything is
      // released.
      await expect(
        tessera.recoverWithRecoveryIdentity({ email, phrase: wrongPhrase }),
      ).rejects.toThrow();
    },
    40_000,
  );

  it(
    'an account with NO recovery identity is refused the same way as a wrong phrase',
    async () => {
      const tessera = new Tessera(h.transport);
      const email = 'recover-unenrolled@example.com';
      await tessera.register({ email, password: utf8('pw') }); // registered, never enrolled

      // 🔴 Anti-enumeration. An unenrolled account must not answer differently from an enrolled one
      // given a wrong phrase, or the recovery endpoint becomes an oracle for who has enrolled —
      // which is exactly what the old /recovery/init endpoint was.
      await expect(
        tessera.recoverWithRecoveryIdentity({ email, phrase: newRecoveryPhrase() }),
      ).rejects.toThrow();
    },
    40_000,
  );

  it('the condemned local-unwrap method is gone', () => {
    const tessera = new Tessera(h.transport) as unknown as Record<string, unknown>;
    // A deletion is only real if nothing still resolves it. Pinned so a well-meaning
    // re-introduction has to argue with a test rather than slip in.
    expect(tessera.recoverWithPhrase).toBeUndefined();
    expect(typeof (tessera.recoverWithRecoveryIdentity as unknown)).toBe('function');
  });
});

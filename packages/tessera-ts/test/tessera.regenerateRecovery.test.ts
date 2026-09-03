import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { init } from '../src/wasm';
import { Tessera } from '../src/tessera';
import { utf8 } from '../src/encoding';
import { startSidecarTransport, type SidecarTransport } from './helpers/sidecarTransport';

/**
 * Phrase ROTATION, and why it is no longer its own method (0.2.0).
 *
 * 🔴 `regenerateRecovery` wrote the new `recovery` WRAP and nothing else — it never touched the
 * recovery OPAQUE record. On an enrolled account that leaves the record authenticating the OLD
 * phrase while the wrap is sealed under the NEW one: the old phrase passes the ceremony and cannot
 * decrypt, the new phrase fails the ceremony. Recovery is dead, with no error at rotation time and
 * no symptom until the day someone needs it.
 *
 * That is the identical half-written state `ciphera-id#68` made unrepresentable on the SERVER,
 * reached from the client side. So the method that produces it was removed rather than documented,
 * and rotation goes through `enrolRecoveryIdentity`, which writes the record and the wrap together.
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

describe('recovery phrase rotation', () => {
  it('the unsafe rotation method is gone', () => {
    const sdk = new Tessera(h.transport) as unknown as Record<string, unknown>;
    expect(sdk.regenerateRecovery).toBeUndefined();
    expect(typeof (sdk.enrolRecoveryIdentity as unknown)).toBe('function');
  });

  it(
    'rotating through enrolRecoveryIdentity preserves the vault and retires the old phrase',
    async () => {
      const sdk = new Tessera(h.transport);
      const email = 'rotate-recovery@example.com';
      const pw = utf8('password-123');
      await sdk.register({ email, password: pw });

      const first = await sdk.enrolRecoveryIdentity({ email, password: pw, reauthToken: 'enr-1' });

      // Seal under the original VMK.
      const s1 = await sdk.login({ email, password: pw });
      const secret = utf8('survives rotation');
      const env = await s1.vault.seal('address', secret);

      const second = await sdk.enrolRecoveryIdentity({ email, password: pw, reauthToken: 'enr-2' });
      expect(second.recoveryPhrase).not.toBe(first.recoveryPhrase);

      // The NEW phrase recovers, and the vault was never re-encrypted.
      const rec = await sdk.recoverWithRecoveryIdentity({ email, phrase: second.recoveryPhrase });
      expect(await rec.vault.open('address', env)).toEqual(secret);
      rec.dispose();

      // 🔑 The OLD phrase is retired at BOTH halves — it fails the ceremony rather than passing it
      // and failing to decrypt. That asymmetry is the whole reason the record and the wrap have to
      // move together: a rotation that moved only the wrap would leave this passing.
      await expect(
        sdk.recoverWithRecoveryIdentity({ email, phrase: first.recoveryPhrase }),
      ).rejects.toThrow();
    },
    60_000,
  );
});

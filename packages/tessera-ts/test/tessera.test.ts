import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { init } from '../src/wasm';
import { Tessera } from '../src/tessera';
import { MalformedEnvelopeError } from '../src/errors';
import { utf8, fromBase64Std } from '../src/encoding';
import { blindIndexString } from '../src/blindIndex';
import { openVaultKey } from '../src/vmk';
import { recoverySecret } from '../src/recovery';
import { open as vaultOpen } from '../src/vault';
import { startSidecarTransport, type SidecarTransport } from './helpers/sidecarTransport';

// Full SDK flow over a REAL sidecar: register → login → vault seal/open. Requires TESSERA_SIDECAR_BIN.
let h: SidecarTransport;

beforeAll(async () => {
  await init();
  h = await startSidecarTransport();
}, 30_000);

afterAll(async () => {
  await h?.stop();
});

describe('Tessera high-level SDK (register / login / vault)', () => {
  it(
    'register returns a 24-word recovery phrase',
    async () => {
      const tessera = new Tessera(h.transport);
      const { recoveryPhrase } = await tessera.register({
        email: 'sdk-register@example.com',
        password: utf8('correct horse battery staple'),
      });
      expect(recoveryPhrase.split(' ')).toHaveLength(24);
    },
    30_000,
  );

  it(
    'login yields a Session whose vault seal/open round-trips, and cross-context open fails',
    async () => {
      const tessera = new Tessera(h.transport);
      const email = 'sdk-login@example.com';
      const password = utf8('hunter2-correct-horse');
      await tessera.register({ email, password });

      const session = await tessera.login({ email, password });
      expect(session.sessionKeyB64).not.toBeNull(); // login path runs an OPAQUE handshake

      const secret = utf8('my home address');
      const env = await session.vault.seal('address', secret);
      expect(await session.vault.open('address', env)).toEqual(secret);

      // A record sealed under one context must not open under another (key separation).
      await expect(session.vault.open('totp', env)).rejects.toBeInstanceOf(MalformedEnvelopeError);
    },
    40_000,
  );

  it(
    'login with the wrong password is rejected',
    async () => {
      const tessera = new Tessera(h.transport);
      const email = 'sdk-wrongpw@example.com';
      await tessera.register({ email, password: utf8('the-right-one') });
      await expect(
        tessera.login({ email, password: utf8('the-wrong-one') }),
      ).rejects.toThrow();
    },
    30_000,
  );
});

describe('registerForMigration (forced SRP→OPAQUE upgrade)', () => {
  it(
    'enrols OPAQUE and returns both wraps WITHOUT putWraps; the new phrase recovers the migrated vault',
    async () => {
      const email = 'sdk-migrate@example.com';
      const password = utf8('old-srp-password');
      const out = await new Tessera(h.transport).registerForMigration({ email, password });

      // Contract: a fresh 24-word phrase plus BOTH wrap blobs are handed back to the caller, which
      // submits them itself to /auth/migrate/opaque (register() would have stored them via putWraps).
      expect(out.recoveryPhrase.split(' ')).toHaveLength(24);
      expect(typeof out.wraps.opaque).toBe('string');
      expect(out.wraps.opaque.length).toBeGreaterThan(0);
      expect(typeof out.wraps.recovery).toBe('string');
      expect(out.wraps.recovery.length).toBeGreaterThan(0);

      // The returned session's vault is immediately usable under the freshly minted VMK.
      const secret = utf8('migrated vault payload');
      const env = await out.session.vault.seal('vault', secret);
      expect(await out.session.vault.open('vault', env)).toEqual(secret);

      // DEFINING DIFFERENCE vs register(): the SDK must NOT have persisted the wraps — the backend
      // commits them atomically inside the migration transaction. The transport's wrap store stays
      // empty for this account, proving putWraps was never called.
      const credentialId = blindIndexString(email);
      expect(await h.transport.getWrap({ credentialId, method: 'opaque' })).toBeNull();
      expect(await h.transport.getWrap({ credentialId, method: 'recovery' })).toBeNull();

      // RECOVERABILITY PROOF (data-loss-critical, §8): the returned recovery wrap, unwrapped with the
      // entropy of the NEW phrase, yields the EXACT VMK that sealed the vault above — so the migrated
      // account is provably recoverable by the phrase the user is about to write down.
      const recovVmk = await openVaultKey(
        fromBase64Std(out.wraps.recovery),
        recoverySecret(out.recoveryPhrase),
        'recovery',
      );
      expect(await vaultOpen(recovVmk, 'vault', env)).toEqual(secret);
    },
    40_000,
  );
});

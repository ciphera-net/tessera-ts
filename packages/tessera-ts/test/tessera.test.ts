import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { init } from '../src/wasm';
import { Tessera } from '../src/tessera';
import { MalformedEnvelopeError } from '../src/errors';
import { utf8 } from '../src/encoding';
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

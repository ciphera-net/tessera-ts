import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { init } from '../src/wasm';
import { Tessera } from '../src/tessera';
import { utf8 } from '../src/encoding';
import { startSidecarTransport, type SidecarTransport } from './helpers/sidecarTransport';

// register additively returns a Session (alongside the recovery phrase) so the
// caller can seal the INITIAL vault immediately — there is no separate VMK to
// reach otherwise. A later login must open what the register session sealed.
let h: SidecarTransport;

beforeAll(async () => {
  await init();
  h = await startSidecarTransport();
}, 30_000);

afterAll(async () => {
  await h?.stop();
});

describe('Tessera.register returns a Session', () => {
  it(
    "register's session seals a record that a later login can open",
    async () => {
      const sdk = new Tessera(h.transport);
      const email = 'reg-session@example.com';
      const password = utf8('correct-horse-reg-session');

      const { recoveryPhrase, session } = await sdk.register({ email, password });
      expect(recoveryPhrase.split(' ')).toHaveLength(24);

      const env = await session.vault.seal('vault', utf8('{"email":"reg-session@example.com"}'));

      const back = await sdk.login({ email, password });
      expect(new TextDecoder().decode(await back.vault.open('vault', env))).toContain('reg-session');
    },
    60_000,
  );
});

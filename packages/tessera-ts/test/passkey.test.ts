import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { init } from '../src/wasm';
import { Tessera } from '../src/tessera';
import { isPasskeySupported } from '../src/passkey';
import { MalformedEnvelopeError } from '../src/errors';
import { utf8 } from '../src/encoding';
import { startSidecarTransport, type SidecarTransport } from './helpers/sidecarTransport';

// WebAuthn-PRF passkey unlock, unit-tested with an INJECTED PRF output (no navigator). The real
// navigator.credentials path (evaluatePrf) is exercised in the Playwright matrix. Requires
// TESSERA_SIDECAR_BIN (enablePasskey re-authenticates via OPAQUE).
let h: SidecarTransport;

// A fresh copy per call: the SDK zeros the PRF output after use, so the provider must not hand out a
// shared buffer it intends to reuse.
const prfOf = (fill: number) => async () => new Uint8Array(32).fill(fill);

beforeAll(async () => {
  await init();
  h = await startSidecarTransport();
}, 30_000);

afterAll(async () => {
  await h?.stop();
});

describe('passkey (WebAuthn-PRF, additive)', () => {
  it('isPasskeySupported() returns false in Node (no PublicKeyCredential) and never throws', async () => {
    await expect(isPasskeySupported()).resolves.toBe(false);
  });

  it(
    'enablePasskey then unlockWithPasskey opens a PRE-EXISTING record (vault preserved; no OPAQUE session)',
    async () => {
      const tessera = new Tessera(h.transport);
      const email = 'passkey-enable@example.com';
      const password = utf8('pw-correct-horse');
      await tessera.register({ email, password });

      // Seal a record via a normal password login.
      const s1 = await tessera.login({ email, password });
      const env = await s1.vault.seal('totp', utf8('secret-otp-seed'));

      // Enable passkey (re-auth + rewrap opaque→webauthn under the injected PRF), then unlock via passkey.
      await tessera.enablePasskey({ email, password, prf: prfOf(0x5a) });
      const s2 = await tessera.unlockWithPasskey({ email, prf: prfOf(0x5a) });
      expect(s2.sessionKeyB64).toBeNull(); // no OPAQUE handshake on the passkey path
      expect(await s2.vault.open('totp', env)).toEqual(utf8('secret-otp-seed'));
    },
    40_000,
  );

  it(
    'unlockWithPasskey with a DIFFERENT PRF output is rejected',
    async () => {
      const tessera = new Tessera(h.transport);
      const email = 'passkey-wrongprf@example.com';
      const password = utf8('pw');
      await tessera.register({ email, password });
      await tessera.enablePasskey({ email, password, prf: prfOf(0x5a) });
      await expect(
        tessera.unlockWithPasskey({ email, prf: prfOf(0x99) }),
      ).rejects.toBeInstanceOf(MalformedEnvelopeError);
    },
    40_000,
  );
});

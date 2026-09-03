import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { init } from '../src/wasm';
import { blindIndexString } from '../src/blindIndex';
import { registerOpaque, loginOpaque, resetPasswordOpaque } from '../src/opaque';
import { InvalidCredentialsError, OpaqueProtocolError } from '../src/errors';
import { utf8 } from '../src/encoding';
import { startSidecarTransport, type SidecarTransport } from './helpers/sidecarTransport';

// Drives opaque.ts end-to-end against a REAL tessera-sidecar (real OPAQUE crypto). Requires
// TESSERA_SIDECAR_BIN. Each test uses a distinct credentialId so the shared in-memory store is clean.
let h: SidecarTransport;

beforeAll(async () => {
  await init();
  h = await startSidecarTransport();
}, 30_000);

afterAll(async () => {
  await h?.stop();
});

describe('opaque.ts orchestration (WASM client ↔ real sidecar)', () => {
  it(
    'registerOpaque → loginOpaque: export_key is 64 bytes and STABLE across register↔login; a session key is returned',
    async () => {
      const cid = blindIndexString('opaque-stable@example.com');
      const pw = utf8('correcthorsebatterystaple');
      const { exportKey: regKey } = await registerOpaque(h.transport, cid, pw);
      const { exportKey: loginKey, sessionKeyB64 } = await loginOpaque(h.transport, cid, pw);
      expect(regKey.length).toBe(64);
      expect(loginKey).toEqual(regKey);
      expect(sessionKeyB64.length).toBeGreaterThan(0);
    },
    30_000,
  );

  it(
    'loginOpaque with the WRONG password rejects with InvalidCredentialsError, not a WASM string',
    async () => {
      const cid = blindIndexString('opaque-wrongpw@example.com');
      await registerOpaque(h.transport, cid, utf8('right-password'));

      // 🔴 This assertion used to be a bare `.rejects.toThrow()` — "something
      // threw". That is why the bug below lived: the Rust core raises
      // `JsError::new(&format!("{e:?}"))`, so a wrong password arrived as an
      // Error whose message was literally `Opaque(InvalidLoginError)`, and
      // id.ciphera.net rendered that string in its sign-in banner (03-09-2026).
      // A test that only asserts THAT it throws cannot see what it threw.
      const err = await loginOpaque(h.transport, cid, utf8('WRONG-password')).then(
        () => null,
        (e: unknown) => e,
      );

      expect(err).toBeInstanceOf(InvalidCredentialsError);
      expect((err as Error).message).toBe('tessera: invalid credentials');
      // No WASM/Rust internals anywhere in what a consumer can read.
      expect((err as Error).message).not.toMatch(/Opaque\(/);
      expect((err as Error).message).not.toMatch(/InvalidLoginError/);
      // Every error this package raises is `tessera:`-prefixed, which is what
      // lets a consumer's display layer recognise it as SDK-internal.
      expect((err as Error).message.startsWith('tessera:')).toBe(true);
    },
    30_000,
  );

  it(
    'a wrong RECOVERY PHRASE is invalid credentials too, distinguishable from a broken ceremony',
    async () => {
      // Same mechanism as a wrong password: the envelope, not the server,
      // decides. /recover needs this to tell "retype your phrase" apart from
      // "recovery is down".
      const cid = blindIndexString('opaque-wrongphrase@example.com');
      await registerOpaque(h.transport, cid, utf8('right-password'));
      const err = await loginOpaque(h.transport, cid, utf8('wrong-phrase-derived-pw')).then(
        () => null,
        (e: unknown) => e,
      );
      expect(err).toBeInstanceOf(InvalidCredentialsError);
      expect(err).not.toBeInstanceOf(OpaqueProtocolError);
    },
    30_000,
  );

  it(
    'a TAMPERED server response is a protocol error, never reported as a wrong password',
    async () => {
      // 🔴 The distinction that matters. Folding this into InvalidCredentials
      // would send a user to reset a password that was already correct, and
      // would hide a real fault behind the one message nobody investigates.
      const cid = blindIndexString('opaque-tampered@example.com');
      const pw = utf8('correcthorsebatterystaple');
      await registerOpaque(h.transport, cid, pw);

      // Corrupt the login response on the wire, leaving the password correct.
      const tampering = {
        ...h.transport,
        loginStart: async (req: Parameters<typeof h.transport.loginStart>[0]) => {
          const res = await h.transport.loginStart(req);
          const bytes = Buffer.from(res.responseB64, 'base64');
          bytes[0] = bytes[0]! ^ 0xff;
          return { ...res, responseB64: bytes.toString('base64') };
        },
      };

      const err = await loginOpaque(tampering, cid, pw).then(
        () => null,
        (e: unknown) => e,
      );
      expect(err).toBeInstanceOf(OpaqueProtocolError);
      expect(err).not.toBeInstanceOf(InvalidCredentialsError);
      expect((err as Error).message).toBe('tessera: OPAQUE ceremony failed');
      // The underlying cause is retained for logs, not for the user.
      expect((err as Error).cause).toBeDefined();
    },
    30_000,
  );

  it(
    'resetPasswordOpaque re-keys auth: the new password logs in, the old one no longer does',
    async () => {
      const cid = blindIndexString('opaque-reset@example.com');
      await registerOpaque(h.transport, cid, utf8('old-password'));
      const { exportKey: newKey } = await resetPasswordOpaque(h.transport, cid, utf8('new-password'));
      expect(newKey.length).toBe(64);

      const { exportKey: loginKey } = await loginOpaque(h.transport, cid, utf8('new-password'));
      expect(loginKey).toEqual(newKey); // login under the new password yields the new export_key
      await expect(loginOpaque(h.transport, cid, utf8('old-password'))).rejects.toThrow();
    },
    40_000,
  );
});

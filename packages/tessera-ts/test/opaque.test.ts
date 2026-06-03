import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { init } from '../src/wasm';
import { blindIndexString } from '../src/blindIndex';
import { registerOpaque, loginOpaque, resetPasswordOpaque } from '../src/opaque';
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
    'loginOpaque with the WRONG password is rejected',
    async () => {
      const cid = blindIndexString('opaque-wrongpw@example.com');
      await registerOpaque(h.transport, cid, utf8('right-password'));
      await expect(loginOpaque(h.transport, cid, utf8('WRONG-password'))).rejects.toThrow();
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

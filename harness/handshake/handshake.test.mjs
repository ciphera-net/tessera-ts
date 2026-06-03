import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
// wasm-pack --target nodejs → CommonJS, auto-initialized on require. NO init() call. Static ESM
// named imports from CJS are unreliable for wasm-bindgen output, so use createRequire.
const require = createRequire(import.meta.url);
const { RegistrationHandle, LoginHandle, blindIndex } = require('../../packages/tessera-ts/wasm/node/tessera.js');

const SIDECAR = process.env.TESSERA_SIDECAR_BIN;          // built release binary
const b64 = (u8) => Buffer.from(u8).toString('base64');   // BASE64_STANDARD (OPAQUE blobs)
const u8  = (s)  => new Uint8Array(Buffer.from(s, 'base64'));
// base64url UNPADDED — exercises the PRODUCTION credential_id encoding path (matches blindIndex.ts).
const toB64Url = (bytes) => b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// One request/response over the UDS using the sidecar's length-prefixed JSON frames.
function rpc(socketPath, obj) {
  return new Promise((resolve, reject) => {
    const sock = net.createConnection(socketPath);
    const payload = Buffer.from(JSON.stringify(obj), 'utf8');
    const len = Buffer.alloc(4); len.writeUInt32BE(payload.length);
    let buf = Buffer.alloc(0), need = -1;
    sock.on('connect', () => sock.write(Buffer.concat([len, payload])));
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (need < 0 && buf.length >= 4) { need = buf.readUInt32BE(0); buf = buf.subarray(4); }
      // destroy() (not end()): we have the full frame, so tear the socket down rather than half-close
      // it — a half-open socket could deliver a trailing 'data' event that re-enters JSON.parse.
      if (need >= 0 && buf.length >= need) { sock.destroy(); resolve(JSON.parse(buf.subarray(0, need).toString('utf8'))); }
    });
    sock.on('error', reject);
  });
}

// TCP-connect-only readiness probe (decoupled from the OPAQUE protocol — resilient to any future
// sidecar response-format change; mirrors tessera-go's waitForSocket).
async function waitForSocket(path) {
  for (let i = 0; i < 60; i++) {
    if (sidecarError) throw new Error(`tessera-sidecar failed to start: ${sidecarError.message}`);
    const ok = await new Promise((res) => {
      const s = net.createConnection(path);
      s.on('connect', () => { s.destroy(); res(true); });
      s.on('error', () => res(false));
    });
    if (ok) return;
    await new Promise(r => setTimeout(r, 50));
  }
  throw new Error('sidecar socket did not accept connections within ~3s');
}

let sidecar, socket, sidecarError = null;
before(async () => {
  if (!SIDECAR) {
    throw new Error('TESSERA_SIDECAR_BIN is not set — build the release sidecar and export its path.');
  }
  const dir = mkdtempSync(join(tmpdir(), 'tessera-'));
  socket = join(dir, 't.sock');
  const setup = join(dir, 'setup.bin');
  await new Promise((res, rej) => {
    const child = spawn(SIDECAR, ['gen-setup', setup], { stdio: 'inherit' });
    child.on('error', rej);  // e.g. ENOENT (bad path) — surface as a rejection, not an uncaught error
    child.on('exit', c => (c === 0 ? res() : rej(new Error(`gen-setup exited with code ${c}`))));
  });
  sidecar = spawn(SIDECAR, ['serve', socket, setup], { stdio: 'inherit' });
  // Record a spawn/runtime failure so waitForSocket surfaces it with a clear message. A ChildProcess
  // 'error' event with no listener becomes an uncaught exception that aborts the runner opaquely.
  sidecar.on('error', (e) => { sidecarError = e; });
  await waitForSocket(socket);
});
after(async () => {
  if (!sidecar) return;
  sidecar.kill();
  await new Promise(r => sidecar.once('close', r));  // deterministic teardown — no zombie on fast CI
});

async function enroll(password, credId) {
  const reg = new RegistrationHandle(password);
  const rs = await rpc(socket, { op: 'register_start', request_b64: b64(reg.request), credential_id: credId });
  assert.equal(rs.result, 'register_start');
  const rf = reg.finish(password, u8(rs.response_b64));
  const fin = await rpc(socket, { op: 'register_finish', upload_b64: b64(rf.upload) });
  assert.equal(fin.result, 'register_finish');
  return fin.password_file_b64;
}
async function login(password, credId, passwordFile) {
  const lh = new LoginHandle(password);
  const ls = await rpc(socket, { op: 'login_start', request_b64: b64(lh.request), password_file_b64: passwordFile, credential_id: credId });
  assert.equal(ls.result, 'login_start');
  const lf = lh.finish(password, u8(ls.response_b64));
  const done = await rpc(socket, { op: 'login_finish', login_id: ls.login_id, finalization_b64: b64(lf.finalization) });
  assert.equal(done.result, 'login_finish');
  return { serverSessionKeyB64: done.session_key_b64, lf };
}

test('wasm OPAQUE interoperates byte-for-byte with the native sidecar; export_key is stable', async () => {
  const password = new TextEncoder().encode('correcthorsebatterystaple');
  const credId = toB64Url(blindIndex('user@example.com')); // production base64url-unpadded path
  const passwordFile = await enroll(password, credId);

  const a = await login(password, credId, passwordFile);
  assert.equal(b64(a.lf.sessionKey), a.serverSessionKeyB64, 'session keys must agree across WASM↔sidecar');
  assert.equal(a.lf.exportKey.length, 64);

  // export_key must be deterministic across independent logins.
  const bLogin = await login(password, credId, passwordFile);
  assert.deepEqual(Array.from(bLogin.lf.exportKey), Array.from(a.lf.exportKey), 'export_key must be stable');
});

test('unknown account → password_file_b64: null yields a timing-safe dummy login_start', async () => {
  const password = new TextEncoder().encode('whatever');
  const credId = toB64Url(blindIndex('nobody@example.com'));
  const lh = new LoginHandle(password);
  // null (not "" and not omitted) is the contract for an unknown account (protocol.rs Option<String>).
  const ls = await rpc(socket, { op: 'login_start', request_b64: b64(lh.request), password_file_b64: null, credential_id: credId });
  assert.equal(ls.result, 'login_start', 'sidecar must return a dummy response, never reveal non-existence');
});

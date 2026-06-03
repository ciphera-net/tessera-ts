// A test Transport backed by a REAL tessera-sidecar (the same binary the Task 6 gate uses). It speaks
// the sidecar's [u32 BE len][JSON] frame protocol for OPAQUE crypto, and keeps in-memory stores for the
// OPAQUE password file and the VMK-wrap blobs — i.e. it plays the role of the app backend + DB. This
// lets the TS SDK (opaque.ts / tessera.ts / recovery) be tested end-to-end against real OPAQUE crypto.
//
// Node-only test helper (uses node:net / node:child_process). Requires TESSERA_SIDECAR_BIN.
import net from 'node:net';
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Transport } from '../../src/transport';

function rpc(socketPath: string, obj: unknown): Promise<any> {
  return new Promise((resolve, reject) => {
    const sock = net.createConnection(socketPath);
    const payload = Buffer.from(JSON.stringify(obj), 'utf8');
    const len = Buffer.alloc(4);
    len.writeUInt32BE(payload.length);
    let buf = Buffer.alloc(0);
    let need = -1;
    sock.on('connect', () => sock.write(Buffer.concat([len, payload])));
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (need < 0 && buf.length >= 4) {
        need = buf.readUInt32BE(0);
        buf = buf.subarray(4);
      }
      if (need >= 0 && buf.length >= need) {
        sock.destroy();
        resolve(JSON.parse(buf.subarray(0, need).toString('utf8')));
      }
    });
    sock.on('error', reject);
  });
}

async function waitForSocket(path: string): Promise<void> {
  for (let i = 0; i < 100; i++) {
    const ok = await new Promise<boolean>((res) => {
      const s = net.createConnection(path);
      s.on('connect', () => {
        s.destroy();
        res(true);
      });
      s.on('error', () => res(false));
    });
    if (ok) return;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error('sidecar socket did not accept connections within ~5s');
}

export interface SidecarTransport {
  transport: Transport;
  stop: () => Promise<void>;
}

export async function startSidecarTransport(): Promise<SidecarTransport> {
  const SIDECAR = process.env.TESSERA_SIDECAR_BIN;
  if (!SIDECAR) {
    throw new Error('TESSERA_SIDECAR_BIN is not set — build the release sidecar and export its path.');
  }
  const dir = mkdtempSync(join(tmpdir(), 'tessera-t-'));
  const socket = join(dir, 't.sock');
  const setup = join(dir, 'setup.bin');
  await new Promise<void>((res, rej) => {
    const child = spawn(SIDECAR, ['gen-setup', setup], { stdio: 'inherit' });
    child.on('error', rej);
    child.on('exit', (c) => (c === 0 ? res() : rej(new Error(`gen-setup exited ${c}`))));
  });
  let sidecarErr: Error | null = null;
  const sidecar: ChildProcess = spawn(SIDECAR, ['serve', socket, setup], { stdio: 'inherit' });
  sidecar.on('error', (e) => {
    sidecarErr = e;
  });
  await waitForSocket(socket);
  if (sidecarErr) throw sidecarErr;

  // In-memory "server DB": OPAQUE password files + VMK-wrap blobs, keyed by credentialId.
  const passwordFiles = new Map<string, string>(); // credentialId → password_file_b64
  const wraps = new Map<string, Record<string, string>>(); // credentialId → { method → blobB64 }

  const transport: Transport = {
    async registerStart({ requestB64, credentialId }) {
      const r = await rpc(socket, { op: 'register_start', request_b64: requestB64, credential_id: credentialId });
      if (r.result !== 'register_start') throw new Error(`register_start: ${JSON.stringify(r)}`);
      return { responseB64: r.response_b64 };
    },
    async registerFinish({ credentialId, uploadB64 }) {
      const r = await rpc(socket, { op: 'register_finish', upload_b64: uploadB64 });
      if (r.result !== 'register_finish') throw new Error(`register_finish: ${JSON.stringify(r)}`);
      passwordFiles.set(credentialId, r.password_file_b64); // server stores it; never returned to browser
    },
    async loginStart({ requestB64, credentialId }) {
      const r = await rpc(socket, {
        op: 'login_start',
        request_b64: requestB64,
        password_file_b64: passwordFiles.get(credentialId) ?? null, // unknown account → null (no sentinel)
        credential_id: credentialId,
      });
      if (r.result !== 'login_start') throw new Error(`login_start: ${JSON.stringify(r)}`);
      return { loginId: r.login_id, responseB64: r.response_b64 };
    },
    async loginFinish({ loginId, finalizationB64 }) {
      const r = await rpc(socket, { op: 'login_finish', login_id: loginId, finalization_b64: finalizationB64 });
      if (r.result !== 'login_finish') throw new Error(`login_finish: ${JSON.stringify(r)}`);
      return { sessionKeyB64: r.session_key_b64 };
    },
    async replacePasswordFile({ credentialId, uploadB64 }) {
      const r = await rpc(socket, { op: 'register_finish', upload_b64: uploadB64 });
      if (r.result !== 'register_finish') throw new Error(`replacePasswordFile: ${JSON.stringify(r)}`);
      passwordFiles.set(credentialId, r.password_file_b64); // overwrite the stored auth record
    },
    async putWraps({ credentialId, wraps: w }) {
      wraps.set(credentialId, { ...(wraps.get(credentialId) ?? {}), ...w });
    },
    async getWrap({ credentialId, method }) {
      const blobB64 = wraps.get(credentialId)?.[method];
      return blobB64 ? { blobB64 } : null;
    },
  };

  const stop = async (): Promise<void> => {
    if (sidecar.exitCode === null) {
      sidecar.kill();
      await new Promise<void>((r) => sidecar.once('close', () => r()));
    }
  };
  return { transport, stop };
}

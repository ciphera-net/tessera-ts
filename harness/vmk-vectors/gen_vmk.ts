// Regenerates the browser-only VMK-wrap conformance vectors using @ciphera-net/tessera.
// Run from packages/tessera-ts (where tsx + node_modules live):
//   npx tsx ../../harness/vmk-vectors/gen_vmk.ts > ../../../ciphera-tessera/conformance/vectors/vmk-wrap.json
//
// VMK-wrap exists ONLY in the browser SDK (tessera-go has no VMK layer) — these are TS-self +
// future-port conformance. Open-parity (the wrap nonce is random) PLUS a wrapKekHex KAT (deterministic
// HKDF). Pure WebCrypto — NO WASM, so it must NOT call init().
import { hkdfSync } from 'node:crypto';
import { wrapVmk, type UnlockMethod } from '../../packages/tessera-ts/src/vmk';

const subtle = globalThis.crypto.subtle;
const toHex = (b: Uint8Array | Buffer) => Buffer.from(b).toString('hex');
const fromHex = (h: string) => new Uint8Array(Buffer.from(h, 'hex'));

// wrapKEK = HKDF-SHA256(methodSecret, salt=32 zero bytes, info="tessera/vmk-wrap/v1/"+method, 32B).
// Derived here via stdlib HKDF, INDEPENDENT of the SDK's non-extractable WebCrypto KEK, purely to PIN
// the value as a KAT. Both implement RFC 5869 with identical params, so they agree by construction —
// and the self-check below proves it empirically against an actual SDK-produced blob.
function deriveWrapKek(secret: Uint8Array, method: UnlockMethod): Uint8Array {
  const info = Buffer.from('tessera/vmk-wrap/v1/' + method, 'utf8');
  return new Uint8Array(hkdfSync('sha256', secret, Buffer.alloc(32), info, 32));
}

// AAD = [0x01] ‖ utf8("tessera/vmk-wrap/v1/"+method) — matches vmk.ts wrapAad().
function wrapAad(method: UnlockMethod): Uint8Array {
  const info = Buffer.from('tessera/vmk-wrap/v1/' + method, 'utf8');
  const aad = new Uint8Array(1 + info.length);
  aad[0] = 0x01;
  aad.set(info, 1);
  return aad;
}

// Self-check: the independently-derived wrapKEK must OPEN the SDK-produced blob (envelope is
// [0x01][nonce 12][AES-GCM ct‖tag 48]). Recovering vmk proves the Node HKDF == the SDK's
// non-extractable WebCrypto wrapKEK, so wrapKekHex is the real KEK, not a guess.
async function assertWrapKekOpens(blob: Uint8Array, secret: Uint8Array, method: UnlockMethod, vmkHex: string) {
  const kek = await subtle.importKey('raw', deriveWrapKek(secret, method), 'AES-GCM', false, ['decrypt']);
  const nonce = blob.subarray(1, 13);
  const ct = blob.subarray(13);
  const pt = new Uint8Array(
    await subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: wrapAad(method) }, kek, ct),
  );
  if (toHex(pt) !== vmkHex) {
    throw new Error(`wrapKEK self-check FAILED for method=${method}: independent KEK did not recover the VMK`);
  }
}

// Wrapped in main() (not top-level await): this file lives outside the "type": "module" package, so
// tsx transforms it as CommonJS, where top-level await is unsupported.
async function main() {
  const vmkHex = '02'.repeat(32);
  const methods: { method: UnlockMethod; secretHex: string }[] = [
    { method: 'opaque', secretHex: '03'.repeat(64) }, // export_key is 64 bytes
    { method: 'recovery', secretHex: '04'.repeat(32) }, // recovery entropy is 32 bytes
    { method: 'webauthn', secretHex: '05'.repeat(32) }, // PRF output is 32 bytes
  ];

  const vectors = [];
  for (const { method, secretHex } of methods) {
    const secret = fromHex(secretHex);
    const blob = await wrapVmk(fromHex(vmkHex), secret, method);
    await assertWrapKekOpens(blob, secret, method, vmkHex);
    vectors.push({ method, methodSecretHex: secretHex, vmkHex, wrapKekHex: toHex(deriveWrapKek(secret, method)), blobHex: toHex(blob) });
  }

  process.stdout.write(
    JSON.stringify(
      {
        kitVersion: '1.0.0',
        suite: '0x01',
        generatedBy: 'tessera-ts harness/vmk-vectors/gen_vmk.ts',
        note: 'browser-only (no Go side). Open-parity (random wrap nonce) + wrapKekHex KAT (deterministic HKDF).',
        vectors,
      },
      null,
      2,
    ) + '\n',
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

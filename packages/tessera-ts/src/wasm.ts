// Isomorphic loader for the tessera-wasm module.
//
// The SDK ships for browsers (wasm-pack `web` target: an ESM whose default export is an async init()
// that fetches the .wasm). The test/SSR path runs in Node (wasm-pack `nodejs` target: CommonJS that
// auto-initializes synchronously on require — there is NO init()). `init()` here picks the right
// target for the environment and is idempotent. WASM-backed APIs (blind index, OPAQUE handles) must
// only be called AFTER `init()` resolves — they throw otherwise (no silent half-initialized state).
//
// Types are imported from the generated `web` declarations (identical class surface to `node`), so
// the WASM package must be built (scripts/build-wasm.sh) before typecheck/test — enforced by CI order.
import type { RegistrationHandle, LoginHandle } from '../wasm/web/tessera.js';

export type { RegistrationHandle, LoginHandle };

interface WasmModule {
  RegistrationHandle: new (password: Uint8Array) => RegistrationHandle;
  LoginHandle: new (password: Uint8Array) => LoginHandle;
  blindIndex: (email: string) => Uint8Array;
}

let mod: WasmModule | null = null;
let loading: Promise<WasmModule> | null = null;

// Detect Node WITHOUT a global `process` type — cast globalThis so this stays browser-SDK type-clean
// (no @types/node, which would let browser code reference Node APIs unchecked).
function isNode(): boolean {
  const g = globalThis as { process?: { versions?: { node?: unknown } } };
  return typeof g.process?.versions?.node === 'string';
}

async function load(): Promise<WasmModule> {
  if (mod) return mod;
  if (!loading) {
    loading = (async (): Promise<WasmModule> => {
      if (isNode()) {
        // nodejs target — CommonJS, auto-initialized on import. NO init() call. Read the full
        // module.exports via the dynamic-import `default` (wasm-bindgen CJS named exports are not
        // reliably hoisted by the ESM↔CJS interop, but `default` is the whole exports object).
        const ns = (await import('../wasm/node/tessera.js')) as { default?: WasmModule };
        mod = ns.default ?? (ns as unknown as WasmModule);
      } else {
        // web target — ESM whose default export is the async init() that loads the .wasm.
        const web = (await import('../wasm/web/tessera.js')) as unknown as {
          default: () => Promise<unknown>;
        } & WasmModule;
        await web.default();
        mod = web;
      }
      return mod!; // assigned in both branches above
    })();
  }
  return loading;
}

/** Idempotent: load + initialize the WASM module. Await once before any WASM-backed API. */
export async function init(): Promise<void> {
  await load();
}

function loaded(): WasmModule {
  if (!mod) throw new Error('tessera: WASM not initialized — await init() first');
  return mod;
}

/** Raw 32-byte blind index from an email (normalization + Argon2id happen inside the WASM core). */
export function blindIndexBytes(email: string): Uint8Array {
  return loaded().blindIndex(email);
}

/** Construct an OPAQUE registration handle (single-use; see the WASM binding). */
export function createRegistrationHandle(password: Uint8Array): RegistrationHandle {
  return new (loaded().RegistrationHandle)(password);
}

/** Construct an OPAQUE login handle (single-use). */
export function createLoginHandle(password: Uint8Array): LoginHandle {
  return new (loaded().LoginHandle)(password);
}

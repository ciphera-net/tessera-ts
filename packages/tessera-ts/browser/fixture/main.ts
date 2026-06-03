// Browser test fixture: loads the SDK (web-wasm path) and exposes a helper object on window.__T
// so Playwright can call SDK functions via page.evaluate().  All inputs/outputs cross the CDP
// serialization boundary as hex strings, booleans, or numbers.
import { init as wasmInit, blindIndexBytes } from '../../src/wasm';
import { blindIndexString } from '../../src/blindIndex';
import { importVaultKey, seal, open } from '../../src/vault';
import { generateAndWrap, openVaultKey, wrapVmk } from '../../src/vmk';
import { evaluatePrf } from '../../src/passkey';
import type { UnlockMethod } from '../../src/vmk';
import type { PrfOptions } from '../../src/passkey';

// ── byte helpers (no Node Buffer) ────────────────────────────────────────────

function toHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
}

function fromHex(h: string): Uint8Array {
  if (h.length % 2 !== 0) throw new Error('odd hex length');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// ── window.__T API ───────────────────────────────────────────────────────────

declare global {
  interface Window {
    __T: typeof helpers;
  }
}

const helpers = {
  /** Initialize the WASM module.  Must be awaited before any other helper. */
  async init(): Promise<void> {
    await wasmInit();
    document.getElementById('status')!.textContent = 'WASM ready';
  },

  /** Compute the blind index for an email; returns base64url-unpadded string (matches vectors). */
  async blindIndex(email: string): Promise<string> {
    return blindIndexString(email);
  },

  /** Blind index as a hex string (32 bytes).  Useful for byte-level assertions. */
  async blindIndexHex(email: string): Promise<string> {
    return toHex(blindIndexBytes(email));
  },

  /**
   * Vault round-trip: seal plaintext under a given key+context, then open it again.
   * Returns { openedHex, crossContextThrew }.
   *  - openedHex: hex of the decrypted plaintext (must equal ptHex input)
   *  - crossContextThrew: true iff opening with a DIFFERENT context threw (oracle-resistance check)
   */
  async vaultRoundTrip(
    keyHex: string,
    context: string,
    ptHex: string,
  ): Promise<{ openedHex: string; crossContextThrew: boolean }> {
    const key = await importVaultKey(fromHex(keyHex));
    const pt = fromHex(ptHex);
    const envelope = await seal(key, context, pt);

    // Correct open
    const opened = await open(key, context, envelope);
    const openedHex = toHex(opened);

    // Wrong-context open — must throw
    let crossContextThrew = false;
    try {
      await open(key, context + '_wrong', envelope);
    } catch {
      crossContextThrew = true;
    }

    return { openedHex, crossContextThrew };
  },

  /**
   * VMK round-trip:
   *   1. generateAndWrap under an 'opaque' method secret
   *   2. openVaultKey with the same secret
   *   3. seal + open a test payload under the recovered VaultKey
   * Returns true if the recovered plaintext matches.
   */
  async vmkRoundTrip(): Promise<boolean> {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { vmk, wraps } = await generateAndWrap({ opaque: secret });
    const blob = wraps.opaque!;

    // Recover the VMK from the wrap
    const recovered = await openVaultKey(blob, secret, 'opaque');

    // Seal a test payload under the original VMK, open under the recovered VMK
    const plaintext = new TextEncoder().encode('vmk-roundtrip-test');
    const envelope = await seal(vmk, 'test', plaintext);
    const decrypted = await open(recovered, 'test', envelope);

    const match = new TextDecoder().decode(decrypted) === 'vmk-roundtrip-test';
    secret.fill(0);
    return match;
  },

  /**
   * evaluatePrf wrapper — forwards serialized PrfOptions (with hex-encoded binary fields) and
   * returns the 32-byte PRF output as hex.
   *
   * opts shape:
   *   create:true  → { create, rpId, rpName, userIdHex, userName, challengeHex }
   *   create:false → { create, rpId, challengeHex, allowCredentialIdHexes? }
   */
  async evaluatePrfHex(
    opts: (
      | { create: true; rpId: string; rpName: string; userIdHex: string; userName: string; challengeHex: string }
      | { create: false; rpId: string; challengeHex: string; allowCredentialIdHexes?: string[] }
    ),
  ): Promise<string> {
    let prfOpts: PrfOptions;
    if (opts.create) {
      prfOpts = {
        create: true,
        rpId: opts.rpId,
        rpName: opts.rpName,
        userId: fromHex(opts.userIdHex),
        userName: opts.userName,
        challenge: fromHex(opts.challengeHex),
      };
    } else {
      prfOpts = {
        create: false,
        rpId: opts.rpId,
        challenge: fromHex(opts.challengeHex),
        allowCredentialIds: opts.allowCredentialIdHexes?.map(fromHex),
      };
    }
    const result = await evaluatePrf(prfOpts);
    return toHex(result);
  },

  /**
   * Full WebAuthn-VMK round-trip:
   *   1. evaluatePrf (create) to register + get the PRF output
   *   2. wrapVmk under that PRF output (method='webauthn')
   *   3. evaluatePrf (get) — must return the SAME PRF output
   *   4. openVaultKey with the second PRF output
   *   5. seal+open a payload to confirm the VaultKey is valid
   *
   * Returns {
   *   prf1Hex: string,   // PRF output from create (may be empty if create() doesn't return PRF)
   *   prf2Hex: string,   // PRF output from get (assertion)
   *   prf3Hex: string,   // PRF output from second get (stability check)
   *   prfStable: boolean,
   *   vmkRoundTrip: boolean,
   *   credentialIdHex: string,
   * }
   *
   * The credentialIdHex from create is passed back so the test can fill allowCredentialIds for get.
   */
  async passkeyVmkRoundTrip(createOpts: {
    rpId: string;
    rpName: string;
    userIdHex: string;
    userName: string;
    challengeHex: string;
  }): Promise<{
    prf1Hex: string;
    prf2Hex: string;
    prf3Hex: string;
    prfStable: boolean;
    vmkRoundTrip: boolean;
    credentialIdHex: string;
  }> {
    // Step 1: create / register
    let prf1Hex = '';
    let credentialIdHex = '';

    // We need to capture the credential id from create, but evaluatePrf only returns the PRF output.
    // So we do the create ceremony directly here to get both the credential id AND the PRF output.
    const PRF_SALT = new TextEncoder().encode('tessera/prf/v1');
    const extensions = { prf: { eval: { first: PRF_SALT } } } as AuthenticationExtensionsClientInputs;

    const cred = (await navigator.credentials.create({
      publicKey: {
        challenge: fromHex(createOpts.challengeHex),
        rp: { id: createOpts.rpId, name: createOpts.rpName },
        user: {
          id: fromHex(createOpts.userIdHex),
          name: createOpts.userName,
          displayName: createOpts.userName,
        },
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 },
          { type: 'public-key', alg: -257 },
        ],
        authenticatorSelection: { userVerification: 'required', residentKey: 'required' },
        extensions,
      },
    })) as PublicKeyCredential | null;

    if (!cred) throw new Error('create: no credential returned');
    credentialIdHex = toHex(new Uint8Array(cred.rawId));

    const createResults = (
      cred.getClientExtensionResults() as { prf?: { results?: { first?: ArrayBuffer | ArrayBufferView } } }
    ).prf?.results?.first;
    if (createResults) {
      const buf = createResults instanceof ArrayBuffer
        ? new Uint8Array(createResults)
        : new Uint8Array(createResults.buffer, createResults.byteOffset, createResults.byteLength);
      prf1Hex = toHex(buf);
    }
    // If prf1Hex is empty, create() didn't return PRF — we'll get it via get() only.

    // Step 2: get PRF via assertion (this is the reliable path)
    const getChallenge = crypto.getRandomValues(new Uint8Array(32));
    const assertCred1 = (await navigator.credentials.get({
      publicKey: {
        challenge: getChallenge,
        rpId: createOpts.rpId,
        allowCredentials: [{ type: 'public-key', id: fromHex(credentialIdHex) }],
        userVerification: 'required',
        extensions,
      },
    })) as PublicKeyCredential | null;

    if (!assertCred1) throw new Error('get 1: no credential returned');
    const get1Results = (
      assertCred1.getClientExtensionResults() as { prf?: { results?: { first?: ArrayBuffer | ArrayBufferView } } }
    ).prf?.results?.first;
    if (!get1Results) throw new Error('get 1: no PRF result — authenticator does not support PRF');
    const prf2 = get1Results instanceof ArrayBuffer
      ? new Uint8Array(get1Results)
      : new Uint8Array(get1Results.buffer, get1Results.byteOffset, get1Results.byteLength);
    const prf2Hex = toHex(prf2);

    // Step 3: wrap a fresh VMK under prf2, then get PRF again and confirm it round-trips
    const method: UnlockMethod = 'webauthn';
    const vmkRaw = crypto.getRandomValues(new Uint8Array(32));
    const blob = await wrapVmk(vmkRaw, prf2, method);

    // Step 4: second assertion — PRF must be STABLE (same bytes)
    const getChallenge2 = crypto.getRandomValues(new Uint8Array(32));
    const assertCred2 = (await navigator.credentials.get({
      publicKey: {
        challenge: getChallenge2,
        rpId: createOpts.rpId,
        allowCredentials: [{ type: 'public-key', id: fromHex(credentialIdHex) }],
        userVerification: 'required',
        extensions,
      },
    })) as PublicKeyCredential | null;

    if (!assertCred2) throw new Error('get 2: no credential returned');
    const get2Results = (
      assertCred2.getClientExtensionResults() as { prf?: { results?: { first?: ArrayBuffer | ArrayBufferView } } }
    ).prf?.results?.first;
    if (!get2Results) throw new Error('get 2: no PRF result');
    const prf3 = get2Results instanceof ArrayBuffer
      ? new Uint8Array(get2Results)
      : new Uint8Array(get2Results.buffer, get2Results.byteOffset, get2Results.byteLength);
    const prf3Hex = toHex(prf3);

    const prfStable = prf2Hex === prf3Hex;

    // Step 5: openVaultKey using prf3 (the second assertion output) and test a vault round-trip
    const recoveredVmk = await openVaultKey(blob, prf3, method);
    const plaintext = new TextEncoder().encode('passkey-vmk-test');
    // We need a separate vault key to seal with; we'll use the vmkRaw directly as vaultKey
    const vaultKey = await importVaultKey(vmkRaw);
    const envelope = await seal(vaultKey, 'passkey-test', plaintext);
    const decrypted = await open(recoveredVmk, 'passkey-test', envelope);
    const roundTripOk = new TextDecoder().decode(decrypted) === 'passkey-vmk-test';
    vmkRaw.fill(0);

    return {
      prf1Hex,
      prf2Hex,
      prf3Hex,
      prfStable,
      vmkRoundTrip: roundTripOk,
      credentialIdHex,
    };
  },
};

window.__T = helpers;

import { describe, it, expect } from 'vitest';
import {
  generateAndWrap,
  openVaultKey,
  unwrapVmkRaw,
  rewrapForMethod,
} from '../src/vmk';
import { seal, open } from '../src/vault';
import { MalformedEnvelopeError } from '../src/errors';

const subtle = globalThis.crypto.subtle;
const rand = (n: number) => crypto.getRandomValues(new Uint8Array(n));

describe('vmk wrap/unwrap per unlock method', () => {
  it('a VMK unwrapped from its wrap opens a record sealed under the generated VMK (interchangeable)', async () => {
    const opaqueSecret = rand(64); // export_key is 64 bytes — pass it WHOLE
    const { vmk, wraps } = await generateAndWrap({ opaque: opaqueSecret });
    expect(wraps.opaque).toBeDefined();

    const record = await seal(vmk, 'address', new TextEncoder().encode('vault payload'));
    const vmk2 = await openVaultKey(wraps.opaque!, opaqueSecret, 'opaque');
    expect(await open(vmk2, 'address', record)).toEqual(new TextEncoder().encode('vault payload'));
  });

  it('unwrapping with the WRONG secret throws MalformedEnvelope', async () => {
    const secret = rand(32);
    const { wraps } = await generateAndWrap({ opaque: secret });
    await expect(openVaultKey(wraps.opaque!, rand(32), 'opaque')).rejects.toBeInstanceOf(
      MalformedEnvelopeError,
    );
    await expect(unwrapVmkRaw(wraps.opaque!, rand(32), 'opaque')).rejects.toBeInstanceOf(
      MalformedEnvelopeError,
    );
  });

  it('unwrapping under a DIFFERENT method than it was wrapped throws MalformedEnvelope', async () => {
    const secret = rand(32);
    const { wraps } = await generateAndWrap({ opaque: secret });
    // Same secret bytes, wrong method label → different AAD + KEK info → auth fails.
    await expect(openVaultKey(wraps.opaque!, secret, 'recovery')).rejects.toBeInstanceOf(
      MalformedEnvelopeError,
    );
  });

  it('the unwrapped VMK is NON-extractable (exportKey raw rejects)', async () => {
    const secret = rand(32);
    const { wraps } = await generateAndWrap({ opaque: secret });
    const vmk = await openVaultKey(wraps.opaque!, secret, 'opaque');
    await expect(subtle.exportKey('raw', vmk)).rejects.toThrow();
  });

  it('rewrapForMethod adds a webauthn wrap WITHOUT re-encrypting the vault', async () => {
    const opaqueSecret = rand(64);
    const { vmk, wraps } = await generateAndWrap({ opaque: opaqueSecret });
    const record = await seal(vmk, 'totp', new TextEncoder().encode('one time secret'));

    const prfSecret = rand(32);
    const webauthnWrap = await rewrapForMethod(
      { blob: wraps.opaque!, secret: opaqueSecret, method: 'opaque' },
      { secret: prfSecret, method: 'webauthn' },
    );
    const vmkViaPasskey = await openVaultKey(webauthnWrap, prfSecret, 'webauthn');
    // The SAME (pre-existing) record opens under the passkey-derived VaultKey — vault never re-encrypted.
    expect(await open(vmkViaPasskey, 'totp', record)).toEqual(
      new TextEncoder().encode('one time secret'),
    );
  });

  it('generateAndWrap with no methods throws (would mint an irrecoverable VMK)', async () => {
    await expect(generateAndWrap({})).rejects.toThrow();
  });

  it('a wrong-length wrap blob (60 or 62 bytes) throws MalformedEnvelope', async () => {
    const secret = rand(32);
    await expect(unwrapVmkRaw(new Uint8Array(60), secret, 'opaque')).rejects.toBeInstanceOf(
      MalformedEnvelopeError,
    );
    await expect(unwrapVmkRaw(new Uint8Array(62), secret, 'opaque')).rejects.toBeInstanceOf(
      MalformedEnvelopeError,
    );
  });
});

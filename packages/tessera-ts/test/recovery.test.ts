import { describe, it, expect } from 'vitest';
import { newRecoveryPhrase, recoverySecret } from '../src/recovery';

describe('recovery (BIP-39, 24 words)', () => {
  it('generates a valid 24-word phrase', () => {
    const phrase = newRecoveryPhrase();
    expect(phrase.split(' ')).toHaveLength(24);
    // round-trips through recoverySecret without throwing (valid checksum)
    expect(recoverySecret(phrase).length).toBe(32);
  });

  it('recoverySecret is deterministic and 32 bytes', () => {
    const phrase = newRecoveryPhrase();
    expect(recoverySecret(phrase)).toEqual(recoverySecret(phrase));
  });

  it('throws on an invalid-checksum phrase', () => {
    // 24 valid words but a deliberately broken checksum (all "abandon" fails the checksum).
    const bad = Array(24).fill('abandon').join(' ');
    expect(() => recoverySecret(bad)).toThrow();
  });

  it('throws when a single word is tampered', () => {
    // Fixed BIP-39 test vector (Trezor, entropy 0x8080...80) with word 0 swapped
    // letter→zoo. The 8-bit checksum only catches a random single-word tamper with
    // probability 255/256, so tampering a *random* phrase is flaky by construction;
    // this specific tampered vector is verified once to fail the checksum and is
    // therefore deterministic forever.
    const valid =
      'letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd ' +
      'amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless';
    expect(recoverySecret(valid).length).toBe(32); // vector itself is valid
    const tampered = valid.replace(/^letter/, 'zoo');
    expect(() => recoverySecret(tampered)).toThrow();
  });
});

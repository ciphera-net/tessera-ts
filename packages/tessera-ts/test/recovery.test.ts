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
    const phrase = newRecoveryPhrase();
    const words = phrase.split(' ');
    // Swap the first word for a different valid wordlist entry → checksum no longer matches.
    words[0] = words[0] === 'zoo' ? 'zone' : 'zoo';
    expect(() => recoverySecret(words.join(' '))).toThrow();
  });
});

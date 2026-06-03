// BIP-39 (24-word / 256-bit) recovery. The recovery WRAP secret is the mnemonic ENTROPY (already
// 256 bits of high entropy) — NOT the PBKDF2 seed: there is no passphrase, the entropy is the secret,
// and using it directly avoids a redundant 2048-round PBKDF2. The phrase is shown to the user ONCE at
// registration; losing it means losing the recovery path (the password path remains).
import { generateMnemonic, mnemonicToEntropy, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';

/** A fresh 24-word (256-bit) recovery phrase. Show to the user ONCE; never persist it. NOTE: the
 *  returned string is immutable (JS strings cannot be zeroed) — minimise its lifetime; the SDK
 *  derives the entropy from it and zeroes THAT, but the phrase string itself cannot be wiped. */
export function newRecoveryPhrase(): string {
  return generateMnemonic(wordlist, 256);
}

/** The 'recovery' VMK-wrap secret = the 32-byte BIP-39 entropy. Throws on an invalid-checksum phrase.
 *  CALLER must zero the returned buffer after wrapping/unwrapping. */
export function recoverySecret(phrase: string): Uint8Array {
  if (!validateMnemonic(phrase, wordlist)) throw new Error('tessera: invalid recovery phrase');
  return mnemonicToEntropy(phrase, wordlist); // 32 bytes
}

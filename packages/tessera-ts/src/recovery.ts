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

/**
 * The recovery phrase, encoded as the aPAKE password for the account's SECOND OPAQUE identity.
 *
 * 🔴 THIS IS A WIRE CONTRACT. It is what the browser hands to OPAQUE when it registers or logs in
 * against the recovery identity, and the server stores only the resulting password file. Change a
 * byte of it after anyone has enrolled and every enrolled recovery identity becomes unopenable —
 * silently, because a wrong password is indistinguishable from a wrong phrase. It is pinned by a
 * known-answer vector (`recoveryPhrasePassword` in `test/vectors.test.ts`) for exactly that reason,
 * in the same spirit as `@ciphera-net/auth`'s blind-index KAT.
 *
 * The encoding is: **NFKD-normalise, split on any whitespace, re-join with single U+0020 spaces,
 * take the UTF-8 bytes.**
 *
 *  - **NFKD** because a mnemonic may be typed, pasted or autocorrected on a platform that composes
 *    accents differently. BIP-39 itself mandates NFKD for exactly this reason, and the English
 *    wordlist is pure ASCII so this is a no-op for us today — it is here so a future non-English
 *    wordlist cannot silently break every enrolled identity.
 *  - **Re-joining on single spaces** normalises the whitespace a human paste introduces: a trailing
 *    newline, a double space, a non-breaking space from a PDF. Without it, two people typing the
 *    same 24 words produce different passwords.
 *
 * 🔑 IT IS DELIBERATELY THE WORDS, NOT THE ENTROPY. The 32-byte entropy is already the `recovery`
 * VMK-WRAP secret. Reusing it as the aPAKE password would couple the two secrets for no gain: an
 * attacker who obtained one would hold the other, and the wrap secret would then transit the OPAQUE
 * ceremony. They are separate derivations of the same phrase, on purpose.
 *
 * Returns a fresh buffer the CALLER should zero after use.
 */
export function recoveryPhrasePassword(phrase: string): Uint8Array {
  // 🔴 CANONICALISE FIRST, THEN VALIDATE. Validating the raw string would reject exactly the input
  // this function exists to accept — a real paste, with a leading space, a tab between two words or
  // a trailing newline. Validate the bytes that are actually going to be used, never a different
  // string that merely resembles them.
  const canonical = phrase.normalize('NFKD').split(/\s+/u).filter(Boolean).join(' ');
  if (!validateMnemonic(canonical, wordlist)) {
    throw new Error('tessera: invalid recovery phrase');
  }
  return new TextEncoder().encode(canonical);
}

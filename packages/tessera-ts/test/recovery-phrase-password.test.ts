import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { recoveryPhrasePassword } from '../src/recovery';

/**
 * 🔴 KNOWN-ANSWER TEST FOR A WIRE CONTRACT.
 *
 * `recoveryPhrasePassword` is what the browser hands to OPAQUE when it registers or logs in against
 * an account's recovery identity. The server keeps only the resulting password file, so a change of
 * one byte here makes every already-enrolled recovery identity unopenable — silently, because a
 * wrong password is indistinguishable from a wrong phrase. There is no migration for that: the
 * server cannot re-derive it, and the user's phrase is the only input.
 *
 * PROVENANCE — this matters more than the test. The expected digest below was NOT produced by
 * running this implementation and pasting the output; deriving the expectation from the subject is
 * what makes a KAT vacuous. It was computed independently in Python directly from the written spec
 * (NFKD → split on whitespace → join with single U+0020 → UTF-8):
 *
 *     canonical = " ".join(unicodedata.normalize("NFKD", phrase).split())
 *     hashlib.sha256(canonical.encode("utf-8")).hexdigest()
 *
 * The phrase itself is the published BIP-39 English vector for all-zero 256-bit entropy, so it is
 * externally verifiable and was not minted by this repo.
 */
const PHRASE =
  'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote';

const VECTOR = {
  utf8Length: 96,
  sha256: 'e96bfc1d78867126dadff72e64807301e9bb837bcf329c86976647e529520528',
} as const;

const sha256 = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');

describe('recoveryPhrasePassword — the phrase→aPAKE-password wire contract', () => {
  it('matches the independently-derived known answer', () => {
    const pw = recoveryPhrasePassword(PHRASE);
    expect(pw.length).toBe(VECTOR.utf8Length);
    expect(sha256(pw)).toBe(VECTOR.sha256);
  });

  it('normalises the whitespace a human paste introduces', () => {
    // A trailing newline, a tab, a double space — all of which a real paste from a password
    // manager, a PDF or a terminal will produce. Without normalisation two people typing the same
    // 24 words derive different passwords and one of them can never recover.
    const messy =
      '  zoo\tzoo\n zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo   vote  ';
    expect(sha256(recoveryPhrasePassword(messy))).toBe(VECTOR.sha256);
  });

  it('is NOT the entropy — the two secrets are deliberately uncoupled', async () => {
    // The 32-byte BIP-39 entropy is the `recovery` VMK-WRAP secret. Reusing it as the aPAKE
    // password would hand an attacker who obtained one the other, and would put the wrap secret
    // through the OPAQUE ceremony. These must never converge.
    const { recoverySecret } = await import('../src/recovery');
    const pw = recoveryPhrasePassword(PHRASE);
    const entropy = recoverySecret(PHRASE);
    expect(entropy.length).toBe(32);
    expect(pw.length).not.toBe(entropy.length);
    expect(sha256(pw)).not.toBe(sha256(entropy));
  });

  it('refuses an invalid phrase rather than deriving something from it', () => {
    // A bad checksum means a mistyped word. Deriving a password anyway would enrol or attempt a
    // login under a password the user can never reproduce.
    expect(() => recoveryPhrasePassword('not a real mnemonic at all')).toThrow(/invalid recovery phrase/);
    // One word altered — checksum fails.
    const bad = PHRASE.replace(/vote$/, 'zoo');
    expect(() => recoveryPhrasePassword(bad)).toThrow(/invalid recovery phrase/);
  });

  it('returns a fresh buffer each call, so the caller can zero it', () => {
    const a = recoveryPhrasePassword(PHRASE);
    const b = recoveryPhrasePassword(PHRASE);
    expect(a).not.toBe(b);
    a.fill(0);
    expect(sha256(b)).toBe(VECTOR.sha256);
  });

  /**
   * 🔴 THIS TEST EXISTS BECAUSE MUTATION TESTING SAID THE NFKD WAS DECORATION.
   *
   * Deleting `.normalize('NFKD')` left every other assertion in this file GREEN — the BIP-39
   * English wordlist is pure ASCII, so NFKD is a no-op on any phrase we can mint today. That is the
   * same shape as an unobservable crypto parameter, and the honest options were to document it as
   * unkillable or to make it observable. It IS observable, so here it is made so.
   *
   * U+FB01 'ﬁ' is the Latin small ligature FI. NFKD decomposes it to the two ASCII characters
   * 'f' + 'i', turning 'ﬁx' back into the wordlist's 'fix'. Real inputs produce exactly this: a
   * password manager, a PDF or a word processor with ligature substitution hands back text a human
   * cannot distinguish from what they typed.
   *
   * Without NFKD the phrase fails its checksum and this THROWS — so a user whose phrase passed
   * through any ligature-substituting surface could never recover, and the failure would look like
   * a mistyped word rather than an encoding bug.
   */
  it('NFKD-normalises, so a ligature-substituted phrase still resolves (and is not merely a no-op)', () => {
    const plain =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon able fix';
    const ligature = plain.replace('fix', '\ufb01x');

    // Precondition: the two strings really are different bytes, or this test proves nothing.
    expect(ligature).not.toBe(plain);
    expect(ligature.normalize('NFKD')).toBe(plain);

    // The contract: both encode to the same password.
    expect(sha256(recoveryPhrasePassword(ligature))).toBe(sha256(recoveryPhrasePassword(plain)));
  });
});

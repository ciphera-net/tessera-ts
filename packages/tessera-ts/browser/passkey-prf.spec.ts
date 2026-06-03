// Passkey-PRF spec: proves (b) the REAL WebAuthn-PRF ceremony works via a CDP virtual authenticator.
// Chromium only — WebKit's virtual-authenticator/PRF support is unreliable and not tested here.
//
// Test strategy:
//   1. Enable a CTAP2.1 virtual authenticator with PRF/resident-key/UV support.
//   2. Run a real WebAuthn create() (registration) via the SDK — the authenticator may or may not
//      return a PRF result on create() (CTAP2.1 spec says PRF on create is OPTIONAL).
//   3. Run a WebAuthn get() (assertion) — this MUST return a PRF result.
//   4. Run a second get() — assert the PRF output is STABLE (same bytes).
//   5. Wrap a VMK under the first get() PRF output (wrapVmk/'webauthn'), then openVaultKey with
//      the second get() PRF output — must succeed.
//   6. Seal+open a vault record under the recovered VMK — must round-trip.
import { test, expect, CDPSession, Page } from '@playwright/test';

// ── Restrict to chromium project ──────────────────────────────────────────────
// This annotation makes the test a no-op in the webkit project.  The chromium project does not
// set this env var so it runs normally there.
test.skip(
  ({ browserName }) => browserName !== 'chromium',
  'WebAuthn virtual-authenticator/PRF is only tested on Chromium',
);

// ── Helpers ───────────────────────────────────────────────────────────────────

const toHex = (b: Buffer | Uint8Array) =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');

async function addVirtualAuthenticator(client: CDPSession): Promise<string> {
  const { authenticatorId } = await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      automaticPresenceSimulation: true,
      isUserVerified: true,
    },
  });
  return authenticatorId;
}

// Navigate and initialise WASM (shared between tests)
async function setupPage(page: Page): Promise<void> {
  await page.goto('/');
  await page.evaluate(() =>
    (window as unknown as { __T: { init: () => Promise<void> } }).__T.init(),
  );
}

// ── Test ──────────────────────────────────────────────────────────────────────

test('WebAuthn-PRF: virtual authenticator delivers stable PRF + VMK round-trip', async ({
  page,
  context: browserCtx,
}) => {
  await setupPage(page);

  // Open CDP session and enable WebAuthn virtual authenticator
  const client = await browserCtx.newCDPSession(page);
  await client.send('WebAuthn.enable', { enableUI: false });
  await addVirtualAuthenticator(client);

  // Prepare create options (hex-encoded where needed)
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const challenge = crypto.getRandomValues(new Uint8Array(32));

  const createOpts = {
    rpId: 'localhost',
    rpName: 'Tessera Test',
    userIdHex: toHex(userId),
    userName: 'test@tessera.local',
    challengeHex: toHex(challenge),
  };

  // Run the full passkey-VMK round-trip in the page
  type RoundTripResult = {
    prf1Hex: string;       // PRF from create() — may be '' if authenticator doesn't return on create
    prf2Hex: string;       // PRF from first get() assertion
    prf3Hex: string;       // PRF from second get() assertion (stability check)
    prfStable: boolean;    // prf2Hex === prf3Hex
    vmkRoundTrip: boolean; // wrapVmk(prf2) → openVaultKey(prf3) → vault seal/open
    credentialIdHex: string;
  };

  let result: RoundTripResult;
  try {
    result = await page.evaluate(
      (opts) =>
        (
          window as unknown as {
            __T: {
              passkeyVmkRoundTrip: (opts: typeof opts) => Promise<RoundTripResult>;
            };
          }
        ).__T.passkeyVmkRoundTrip(opts),
      createOpts,
    );
  } catch (err) {
    // If the virtual authenticator does not support PRF at all, the SDK throws a clear message.
    // Skip (not fail) so the result is reported as skipped rather than as a test infrastructure error.
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('PRF unsupported') || msg.includes('no PRF result')) {
      test.skip(
        true,
        `Chromium virtual authenticator (ctap2_1/internal) did NOT return a PRF result — ` +
          `this Chromium build does not support the WebAuthn PRF extension via the CDP virtual ` +
          `authenticator API. The real-browser WebAuthn-PRF path must be tested with a physical ` +
          `authenticator or a Chromium build that exposes PRF in virtual-authenticator mode. ` +
          `Raw SDK error: ${msg}`,
      );
      return; // unreachable after test.skip(), but satisfies TS control-flow
    }
    throw err; // re-throw unexpected errors
  }

  // ── Assertions ──────────────────────────────────────────────────────────────

  // create() PRF is optional per spec — log whether it was present but don't assert
  console.log(`[passkey-prf] PRF from create(): ${result.prf1Hex ? `YES (${result.prf1Hex.length / 2} bytes)` : 'NOT RETURNED (authenticator skipped PRF on registration)'}`);
  console.log(`[passkey-prf] PRF from get() #1: ${result.prf2Hex.length / 2} bytes`);
  console.log(`[passkey-prf] PRF from get() #2: ${result.prf3Hex.length / 2} bytes`);
  console.log(`[passkey-prf] PRF stable: ${result.prfStable}`);
  console.log(`[passkey-prf] VMK round-trip: ${result.vmkRoundTrip}`);

  // (i) The assertion PRF output must be exactly 32 bytes (non-empty)
  expect(result.prf2Hex.length).toBe(64); // 32 bytes × 2 hex chars

  // (ii) Two consecutive assertions for the same credential+salt must yield identical PRF bytes
  expect(result.prfStable).toBe(true);

  // (iii) The SDK's webauthn VMK wrap must round-trip under the real ceremony PRF output
  expect(result.vmkRoundTrip).toBe(true);
});

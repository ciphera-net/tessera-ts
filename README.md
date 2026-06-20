# @ciphera-net/tessera

Browser SDK for [Tessera](https://github.com/ciphera-net/tessera), Ciphera's open-source
**zero-knowledge identity** system: OPAQUE (RFC 9807) password authentication where the password
never reaches the server, plus a client-encrypted vault. The cryptography runs in WebAssembly
(compiled from the shared Rust core) with a WebCrypto vault layer.

> [!NOTE]
> **Security status: self-reviewed; not yet independently audited.** Read the
> [security model](https://github.com/ciphera-net/tessera/blob/main/docs/THREAT-MODEL.md) and
> [self-audit](https://github.com/ciphera-net/tessera/blob/main/docs/SELF-AUDIT.md), and review the
> code, before relying on it for anything critical.

## Install

```bash
npm install @ciphera-net/tessera
```

## What it provides

- **OPAQUE (RFC 9807) authentication** — the password never reaches the server in any form; the
  server stores only an opaque registration record. The handshake's `export_key` wraps the vault
  master key (VMK), then is zeroed.
- **Argon2id blind index** — a deterministic, pseudonymous account-lookup key derived from the
  email on-device; the plaintext email never hits the server.
- **AES-256-GCM vault** — versioned, context-bound envelope (`seal` / `open`).
- **BIP-39 (24-word) recovery** and **WebAuthn-PRF passwordless unlock** (additive).

It is byte-for-byte interoperable with the Go server SDK and the Rust sidecar via the shared core
and the canonical conformance kit.

## Repository layout

This repo is a small workspace; the published package lives in
[`packages/tessera-ts/`](./packages/tessera-ts) — see its
[README](./packages/tessera-ts/README.md) for the full API, the `Transport` interface, usage
examples, and the security model. The WASM bindings are in [`crates/tessera-wasm/`](./crates/tessera-wasm)
(compiled from the public Rust core, pinned by commit).

## The Tessera repos

| Repo | What |
|------|------|
| [`ciphera-net/tessera`](https://github.com/ciphera-net/tessera) | Rust OPAQUE core + sidecar + conformance kit + docs |
| [`ciphera-net/tessera-go`](https://github.com/ciphera-net/tessera-go) | Go server SDK |
| [`ciphera-net/tessera-ts`](https://github.com/ciphera-net/tessera-ts) (this repo) | Browser SDK — npm `@ciphera-net/tessera` |

## Build from source

```bash
cd packages/tessera-ts
npm install
npm run build        # wasm-pack (web + node) + tsc
npm test             # vitest
```

## License

[Apache-2.0](./LICENSE). Self-host, modify, and redistribute (including in proprietary products),
subject to the license terms.

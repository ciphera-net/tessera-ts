#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"   # repo root
cd "$ROOT/crates/tessera-wasm"
wasm-pack build --release --target web    --out-dir "$ROOT/packages/tessera-ts/wasm/web"    --out-name tessera
wasm-pack build --release --target nodejs --out-dir "$ROOT/packages/tessera-ts/wasm/node"   --out-name tessera

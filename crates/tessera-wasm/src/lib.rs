//! wasm-bindgen bindings for Tessera's browser client. Pure crypto, raw bytes in/out — base64
//! encoding is the TS layer's job (the parity contract is about the BYTES). All crypto delegates to
//! `tessera` so the browser and the native sidecar share ONE core.

use tessera::blind_index::blind_index_bytes;
use tessera::client::{self, LoginState, RegistrationState};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

// SECRET HYGIENE: every error type passed here is STRUCTURAL — opaque-ke's `ProtocolError` variants
// and `argon2::Error` variants carry only variant names / sizes / counts, never password or key
// bytes — so formatting `{e:?}` into the JsError message cannot leak secret material. Keep it that
// way: never add an error variant that embeds user input or key material into its Debug output.
fn to_js<E: core::fmt::Debug>(e: E) -> JsError {
    JsError::new(&format!("{e:?}"))
}

// ---- Registration ----

#[wasm_bindgen]
pub struct RegistrationHandle {
    state: Option<RegistrationState>,
    request: Vec<u8>,
}

#[wasm_bindgen]
impl RegistrationHandle {
    /// Start registration from a password. `request` carries the RegistrationRequest to relay.
    #[wasm_bindgen(constructor)]
    pub fn new(password: &[u8]) -> Result<RegistrationHandle, JsError> {
        let (request, state) = client::register_start(password).map_err(to_js)?;
        Ok(Self {
            state: Some(state),
            request,
        })
    }

    #[wasm_bindgen(getter)]
    pub fn request(&self) -> Vec<u8> {
        self.request.clone()
    }

    /// Finish registration. Consumes the handle's state (single-use; a second call errors). Returns
    /// the upload to relay and the 64-byte export_key (CLIENT-ONLY — caller must never transmit it).
    pub fn finish(
        &mut self,
        password: &[u8],
        response: &[u8],
    ) -> Result<RegistrationFinish, JsError> {
        let state = self
            .state
            .take()
            .ok_or_else(|| JsError::new("registration already finished"))?;
        let (upload, export_key) =
            client::register_finish(state, password, response).map_err(to_js)?;
        Ok(RegistrationFinish { upload, export_key })
    }
}

#[wasm_bindgen]
pub struct RegistrationFinish {
    upload: Vec<u8>,
    export_key: Vec<u8>,
}

#[wasm_bindgen]
impl RegistrationFinish {
    #[wasm_bindgen(getter)]
    pub fn upload(&self) -> Vec<u8> {
        self.upload.clone()
    }
    #[wasm_bindgen(getter, js_name = exportKey)]
    pub fn export_key(&self) -> Vec<u8> {
        self.export_key.clone()
    }
}

// Best-effort zeroing of the export_key copy held in WASM linear memory when JS drops/frees the
// struct (wasm-bindgen runs Drop on .free()/GC). Defense-in-depth only: a getter hands a CLONE to
// JS, so the TS caller must ALSO zero its Uint8Array. Does not reach round-key schedules.
// ONLY the secret is zeroed: `export_key` is client-only vault key material; `upload` (like login's
// `finalization` and the handles' `request`) is a PUBLIC OPAQUE wire message relayed to the server,
// not secret, so it is intentionally not zeroized.
impl Drop for RegistrationFinish {
    fn drop(&mut self) {
        self.export_key.zeroize();
    }
}

// ---- Login ----

#[wasm_bindgen]
pub struct LoginHandle {
    state: Option<LoginState>,
    request: Vec<u8>,
}

#[wasm_bindgen]
impl LoginHandle {
    #[wasm_bindgen(constructor)]
    pub fn new(password: &[u8]) -> Result<LoginHandle, JsError> {
        let (request, state) = client::login_start(password).map_err(to_js)?;
        Ok(Self {
            state: Some(state),
            request,
        })
    }

    #[wasm_bindgen(getter)]
    pub fn request(&self) -> Vec<u8> {
        self.request.clone()
    }

    /// Finish login (single-use). Returns finalization (relay), session_key, export_key (CLIENT-ONLY).
    pub fn finish(&mut self, password: &[u8], response: &[u8]) -> Result<LoginFinish, JsError> {
        let state = self
            .state
            .take()
            .ok_or_else(|| JsError::new("login already finished"))?;
        let (finalization, session_key, export_key) =
            client::login_finish(state, password, response).map_err(to_js)?;
        Ok(LoginFinish {
            finalization,
            session_key,
            export_key,
        })
    }
}

#[wasm_bindgen]
pub struct LoginFinish {
    finalization: Vec<u8>,
    session_key: Vec<u8>,
    export_key: Vec<u8>,
}

#[wasm_bindgen]
impl LoginFinish {
    #[wasm_bindgen(getter)]
    pub fn finalization(&self) -> Vec<u8> {
        self.finalization.clone()
    }
    #[wasm_bindgen(getter, js_name = sessionKey)]
    pub fn session_key(&self) -> Vec<u8> {
        self.session_key.clone()
    }
    #[wasm_bindgen(getter, js_name = exportKey)]
    pub fn export_key(&self) -> Vec<u8> {
        self.export_key.clone()
    }
}

impl Drop for LoginFinish {
    fn drop(&mut self) {
        self.export_key.zeroize();
        self.session_key.zeroize();
    }
}

// ---- Blind index ----

/// Derive the 32-byte blind index from an email. The params/normalization/salt live in the core
/// crate (`tessera::blind_index`) as the single source of truth; this is a thin binding.
#[wasm_bindgen(js_name = blindIndex)]
pub fn blind_index(email: &str) -> Result<Vec<u8>, JsError> {
    Ok(blind_index_bytes(email).map_err(to_js)?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tessera::server;
    use tessera::suite::{load_server_setup, new_server_setup};
    use wasm_bindgen_test::wasm_bindgen_test;

    // A finished RegistrationHandle is spent: the FIRST finish (a real round-trip) succeeds and
    // consumes the state via Option::take; the SECOND finish must fail with "already finished". A
    // real round-trip (not a garbage response) is required — otherwise BOTH calls would error on
    // deserialize and the test would pass even if single-use were broken (false confidence).
    #[wasm_bindgen_test]
    fn registration_finish_is_single_use() {
        let setup = load_server_setup(&new_server_setup()).unwrap();
        let password = b"correct horse";
        let mut handle = RegistrationHandle::new(password).unwrap();
        let response = server::register_start(&setup, &handle.request(), b"creds").unwrap();

        let first = handle.finish(password, &response);
        assert!(
            first.is_ok(),
            "first finish must succeed on a valid response"
        );

        let second = handle.finish(password, &response);
        assert!(
            second.is_err(),
            "a spent registration handle must reject reuse"
        );
    }
}

use irmaseal_core::util::KeySet;
use irmaseal_core::Error as IRMASealError;
use irmaseal_core::{Identity, PublicKey, UserSecretKey};
use irmaseal_core::{Metadata, MetadataCreateResult, MetadataReader, MetadataReaderResult};
use irmaseal_core::{
    IV_SIZE, KEY_SIZE, MAC_IDENTIFIER, MAC_SIZE, SYMMETRIC_CRYPTO_BLOCKSIZE,
    SYMMETRIC_CRYPTO_IDENTIFIER,
};
use js_sys::Error as JsError;
use js_sys::{Date, Uint8Array};
use std::string::String;
use wasm_bindgen::prelude::*;

pub enum Error {
    Seal(IRMASealError),
}

impl From<Error> for JsValue {
    fn from(err: Error) -> Self {
        JsError::new(match err {
            Error::Seal(e) => match e {
                IRMASealError::NotIRMASEAL => "Not IRMASEAL",
                IRMASealError::IncorrectVersion => "Incorrect version",
                IRMASealError::ConstraintViolation => "Constraint violation",
                IRMASealError::FormatViolation => "Format violation",
            },
        })
        .into()
    }
}

#[wasm_bindgen(inspectable)]
pub struct EncryptionConstants {
    pub key_size: usize,
    pub iv_size: usize,
    pub block_size: usize,
    pub mac_size: usize,
    #[wasm_bindgen(skip)]
    pub symmetric_id: String,
    #[wasm_bindgen(skip)]
    pub verifier_id: String,
}

#[wasm_bindgen]
impl EncryptionConstants {
    #[wasm_bindgen(getter)]
    pub fn symmetric_id(&self) -> JsValue {
        JsValue::from_str(&self.symmetric_id)
    }
    #[wasm_bindgen(getter)]
    pub fn verifier_id(&self) -> JsValue {
        JsValue::from_str(&self.verifier_id)
    }
}

#[wasm_bindgen(js_name = ENCRYPTION_CONSTANTS)]
pub fn constants() -> EncryptionConstants {
    EncryptionConstants {
        key_size: KEY_SIZE,
        iv_size: IV_SIZE,
        block_size: SYMMETRIC_CRYPTO_BLOCKSIZE,
        mac_size: MAC_SIZE,
        symmetric_id: SYMMETRIC_CRYPTO_IDENTIFIER.to_owned(),
        verifier_id: MAC_IDENTIFIER.to_owned(),
    }
}

#[wasm_bindgen(js_name = KeySet)]
pub struct WrappedKeyset(KeySet);

#[wasm_bindgen(js_class = KeySet)]
impl WrappedKeyset {
    #[wasm_bindgen(getter)]
    pub fn aes_key(&self) -> Uint8Array {
        let key = Uint8Array::new_with_length(32);
        key.copy_from(&self.0.aes_key);
        key
    }
    #[wasm_bindgen(getter)]
    pub fn mac_key(&self) -> Uint8Array {
        let key = Uint8Array::new_with_length(32);
        key.copy_from(&self.0.mac_key);
        key
    }
}

#[wasm_bindgen(js_name = Metadata)]
pub struct WrappedMetadata(Metadata);

#[wasm_bindgen(js_class = Metadata)]
impl WrappedMetadata {
    pub fn derive_keys(&self, usk: &str) -> Result<WrappedKeyset, JsValue> {
        let key: UserSecretKey =
            serde_json::from_str(&serde_json::to_string(usk).unwrap()[..]).unwrap();
        let key_set = self.0.derive_keys(&key).map_err(Error::Seal)?;
        Ok(WrappedKeyset(key_set))
    }

    pub fn to_json(&self) -> Result<JsValue, JsValue> {
        let json = serde_json::to_string(&self.0).unwrap();
        let obj = js_sys::JSON::parse(&json).unwrap();

        let iv = js_sys::Reflect::get(&obj, &JsValue::from_str("iv"))?;
        let ct = js_sys::Reflect::get(&obj, &JsValue::from("ciphertext"))?;

        js_sys::Reflect::set(&obj, &JsValue::from_str("iv"), &Uint8Array::new(&iv))?;
        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("ciphertext"),
            &Uint8Array::new(&ct),
        )?;

        Ok(obj.into())
    }
}

#[wasm_bindgen(js_name = MetadataCreateResult)]
pub struct WrappedMetadataCreateResult(MetadataCreateResult);

#[wasm_bindgen(js_class = MetadataCreateResult)]
impl WrappedMetadataCreateResult {
    #[wasm_bindgen(constructor)]
    pub fn new(
        attribute_type: &str,
        attribute_value: &str,
        public_key: &str,
    ) -> Result<WrappedMetadataCreateResult, JsValue> {
        let now = (Date::now() as u64) / 1000;
        let mut rng = rand::thread_rng();
        let id = Identity::new(now, attribute_type, Some(attribute_value)).map_err(Error::Seal)?;
        let pkey = PublicKey::from_base64(public_key).unwrap();
        let res = Metadata::new(id, &pkey, &mut rng).map_err(Error::Seal)?;
        Ok(WrappedMetadataCreateResult(res))
    }

    #[wasm_bindgen(getter)]
    pub fn metadata(&self) -> WrappedMetadata {
        WrappedMetadata(self.0.metadata.clone())
    }

    #[wasm_bindgen(getter)]
    pub fn header(&self) -> Uint8Array {
        let js_header = Uint8Array::new_with_length(self.0.header.len() as u32);
        js_header.copy_from(&self.0.header);
        js_header
    }

    #[wasm_bindgen(getter)]
    pub fn keys(&self) -> WrappedKeyset {
        WrappedKeyset(self.0.keys.clone())
    }
}

#[wasm_bindgen(js_name = MetadataReader)]
pub struct WrappedMetadataReader(MetadataReader);

#[wasm_bindgen(js_class = MetadataReader)]
impl WrappedMetadataReader {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WrappedMetadataReader {
        WrappedMetadataReader(MetadataReader::new())
    }

    pub fn feed(&mut self, food: &Uint8Array) -> Result<WrappedMetadataReaderResult, JsValue> {
        let res = self
            .0
            .write(food.to_vec().as_slice())
            .map_err(Error::Seal)?;

        Ok(WrappedMetadataReaderResult(res))
    }

    #[wasm_bindgen(getter)]
    pub fn safe_write_size(&self) -> usize {
        self.0.get_safe_write_size()
    }
}

#[wasm_bindgen(js_name = MetadataReaderResult)]
pub struct WrappedMetadataReaderResult(MetadataReaderResult);

#[wasm_bindgen(js_class = MetadataReaderResult)]
impl WrappedMetadataReaderResult {
    #[wasm_bindgen(getter)]
    pub fn done(&self) -> bool {
        match self.0 {
            MetadataReaderResult::Hungry => false,
            MetadataReaderResult::Saturated { .. } => true,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn metadata(&self) -> Result<WrappedMetadata, JsValue> {
        match &self.0 {
            MetadataReaderResult::Saturated { metadata: m, .. } => Ok(WrappedMetadata(m.clone())),
            MetadataReaderResult::Hungry => {
                Err(JsError::new("metadata reader is not yet satisfied").into())
            }
        }
    }

    #[wasm_bindgen(getter)]
    pub fn header(&self) -> Result<JsValue, JsValue> {
        match &self.0 {
            MetadataReaderResult::Saturated { header: h, .. } => {
                let js_header = Uint8Array::new_with_length(h.len() as u32);
                js_header.copy_from(&h);
                Ok(js_header.into())
            }
            MetadataReaderResult::Hungry => {
                Err(JsError::new("metadata reader is not yet satisfied").into())
            }
        }
    }
}

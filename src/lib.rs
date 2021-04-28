#![no_std]

use core::convert::TryFrom;
use irmaseal_core::util::ArrayVec;
use irmaseal_core::util::KeySet;
use irmaseal_core::Error as IRMASealError;
use irmaseal_core::{Identity, PublicKey, UserSecretKey};
use irmaseal_core::{Metadata, MetadataCreateResult, MetadataReader, MetadataReaderResult};
use js_sys::Error as JsError;
use js_sys::{Date, Uint8Array};
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

#[wasm_bindgen(catch)]
pub fn new_metadata(
    attribute_type: &str,
    attribute_value: &str,
    public_key: &str,
) -> Result<JsValue, JsValue> {
    let now = (Date::now() as u64) / 1000;
    let mut rng = rand::thread_rng();
    let id = Identity::new(now, attribute_type, Some(attribute_value)).map_err(Error::Seal)?;
    let pkey = PublicKey::from_base64(public_key).unwrap();

    let MetadataCreateResult {
        header,
        metadata,
        keys,
    } = Metadata::new(id, &pkey, &mut rng).map_err(Error::Seal)?;

    let json = serde_json::to_string(&metadata).unwrap();
    let metadata_str = JsValue::from_str(&json);

    let arr = Uint8Array::try_from(header.as_slice()).unwrap();

    let obj = js_sys::Object::new();
    let keys_obj = js_sys::Object::new();

    let aes_key = Uint8Array::new_with_length(32);
    aes_key.copy_from(&keys.aes_key);
    let mac_key = Uint8Array::new_with_length(32);
    mac_key.copy_from(&keys.mac_key);

    js_sys::Reflect::set(&keys_obj, &"aesKey".into(), &aes_key).unwrap();
    js_sys::Reflect::set(&keys_obj, &"macKey".into(), &mac_key).unwrap();

    js_sys::Reflect::set(&obj, &"header".into(), &arr).unwrap();
    js_sys::Reflect::set(&obj, &"keys".into(), &keys_obj).unwrap();
    js_sys::Reflect::set(&obj, &"metadata".into(), &metadata_str).unwrap();

    Ok(obj.into())
}

#[wasm_bindgen(catch)]
pub fn feed(food: &Uint8Array) -> Result<JsValue, JsValue> {
    let mut reader = MetadataReader::new();
    let res = reader
        .write(food.to_vec().as_slice())
        .map_err(Error::Seal)?;

    let obj = js_sys::Object::new();
    match res {
        MetadataReaderResult::Hungry => {
            js_sys::Reflect::set(&obj, &"done".into(), &JsValue::from_bool(false)).unwrap();
        }
        MetadataReaderResult::Saturated {
            unconsumed: _,
            header,
            metadata,
        } => {
            let js_header = Uint8Array::new_with_length(header.len() as u32);
            js_header.copy_from(&header);
            let json = serde_json::to_string(&metadata).unwrap();
            let metadata_str = JsValue::from_str(&json);

            js_sys::Reflect::set(&obj, &"done".into(), &JsValue::from_bool(true)).unwrap();
            js_sys::Reflect::set(&obj, &"header".into(), &js_header).unwrap();
            js_sys::Reflect::set(&obj, &"metadata".into(), &metadata_str).unwrap();
        }
    }
    Ok(obj.into())
}

#[wasm_bindgen(catch)]
pub fn decaps(ciphertext: &Uint8Array, usk: &str) -> Result<JsValue, JsValue> {
    let pkey: UserSecretKey =
        serde_json::from_str(&serde_json::to_string(usk).unwrap()[..]).unwrap(); // this is ugly
    let cipherbytes = ciphertext.to_vec();
    let av = ArrayVec::try_from(cipherbytes.as_slice()).unwrap();
    let keys: KeySet = irmaseal_core::util::decaps(&av, &pkey).map_err(Error::Seal)?;

    let aes_key = Uint8Array::new_with_length(32);
    aes_key.copy_from(&keys.aes_key);
    let mac_key = Uint8Array::new_with_length(32);
    mac_key.copy_from(&keys.mac_key);

    let keys_obj = js_sys::Object::new();
    js_sys::Reflect::set(&keys_obj, &"aesKey".into(), &aes_key).unwrap();
    js_sys::Reflect::set(&keys_obj, &"macKey".into(), &mac_key).unwrap();
    Ok(keys_obj.into())
}

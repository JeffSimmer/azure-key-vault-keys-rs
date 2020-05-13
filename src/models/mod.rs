use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeyVaultErrorMessage {
    pub error: KeyVaultError,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeyVaultError {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeyVaultKey {
    pub key: JsonWebKey,
    pub attributes: Attributes,
    #[serde(default = "Default::default")]
    pub tags: HashMap<String, String>,

    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyList {
    pub value: Vec<KeyListEntry>,
    pub next_link: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeyListEntry {
    pub kid: String,
    pub attributes: Attributes,

    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attributes {
    pub enabled: bool,
    #[serde(with = "timestamp")]
    pub created: DateTime<Utc>,
    #[serde(with = "timestamp")]
    pub updated: DateTime<Utc>,
    #[serde(
        with = "optional_timestamp",
        default = "Default::default",
        skip_serializing_if = "Option::is_none"
    )]
    pub exp: Option<DateTime<Utc>>,
    #[serde(
        with = "optional_timestamp",
        default = "Default::default",
        skip_serializing_if = "Option::is_none"
    )]
    pub nbf: Option<DateTime<Utc>>,
    #[serde(default = "Default::default", skip_serializing_if = "Option::is_none")]
    pub recovery_level: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JsonWebKey {
    pub kid: String,
    pub key_ops: Vec<String>,

    #[serde(flatten)]
    pub key: Key,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Key {
    EcJsonWebKey(EcJsonWebKey),
    RsaJsonWebKey(RsaJsonWebKey),
    SymmetricJsonWebKey(SymmetricJsonWebKey),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RsaJsonWebKey {
    pub kty: String,

    // Public parameters
    #[serde(with = "trimmed_base64url")]
    pub e: Vec<u8>,
    #[serde(with = "trimmed_base64url")]
    pub n: Vec<u8>,

    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EcJsonWebKey {
    pub kty: String,
    pub crv: String,

    // Public parameters
    #[serde(with = "base64url")]
    pub x: Vec<u8>,
    #[serde(with = "base64url")]
    pub y: Vec<u8>,

    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl EcJsonWebKey {
    pub fn q(&self) -> Vec<u8> {
        // First byte of 0x04 indicates uncompressed (https://tools.ietf.org/html/rfc5480#section-2.2)
        [&[0x04], &self.x[..], &self.y[..]].concat()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SymmetricJsonWebKey {
    pub kty: String,

    #[serde(with = "base64url")]
    pub k: Vec<u8>,

    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CreateKeyOptions {
    #[serde(skip_serializing, default = "Default::default")]
    pub name: String,
    pub key_ops: Vec<String>,
    #[serde(default = "Default::default", skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Attributes>,
    #[serde(default = "Default::default", skip_serializing_if = "Option::is_none")]
    pub tags: Option<HashMap<String, String>>,
    pub kty: String,

    #[serde(flatten)]
    pub key_options: KeyOptions,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KeyOptions {
    Ec(EcOptions),
    Rsa(RsaOptions),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EcOptions {
    pub crv: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RsaOptions {
    pub key_size: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignRequest {
    pub alg: String,

    #[serde(with = "base64url")]
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub alg: String,

    #[serde(with = "base64url")]
    pub digest: Vec<u8>,

    #[serde(with = "base64url")]
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EncryptRequest {
    pub alg: String,

    #[serde(with = "base64url")]
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DecryptRequest {
    pub alg: String,

    #[serde(with = "base64url")]
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WrapRequest {
    pub alg: String,

    #[serde(with = "base64url")]
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UnwrapRequest {
    pub alg: String,

    #[serde(with = "base64url")]
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifyResult {
    pub value: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Backup {
    #[serde(with = "base64url")]
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeyOperationResult {
    pub kid: String,

    #[serde(with = "base64url")]
    pub value: Vec<u8>,
}

pub mod base64url {
    use serde::de::{Deserializer, Error};
    use serde::ser::Serializer;
    use serde::Deserialize;
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).and_then(|string| {
            base64::decode_config(&string, base64::URL_SAFE_NO_PAD)
                .map_err(|err| Error::custom(err.to_string()))
        })
    }

    pub fn serialize<S>(vec: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64::encode_config(vec, base64::URL_SAFE_NO_PAD))
    }
}

pub mod trimmed_base64url {
    use serde::de::Deserializer;
    use serde::ser::Serializer;
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        super::base64url::deserialize(deserializer)
    }

    pub fn serialize<S>(vec: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64::encode_config(
            &vec.iter()
                .copied()
                .skip_while(|&v| v == 0u8)
                .collect::<Vec<u8>>(),
            base64::URL_SAFE_NO_PAD,
        ))
    }
}

pub mod timestamp {
    use chrono::{DateTime, NaiveDateTime, Utc};
    use serde::de::Deserializer;
    use serde::ser::Serializer;
    use serde::Deserialize;
    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        i64::deserialize(deserializer).and_then(|ts| {
            Ok(DateTime::<Utc>::from_utc(
                NaiveDateTime::from_timestamp(ts, 0),
                Utc,
            ))
        })
    }

    pub fn serialize<S>(dt: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i64(dt.timestamp())
    }
}

pub mod optional_timestamp {
    use chrono::{DateTime, Utc};
    use serde::de::Deserializer;
    use serde::ser::Serializer;
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Some(super::timestamp::deserialize(deserializer)?))
    }

    pub fn serialize<S>(dt: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match dt {
            Some(dt) => super::timestamp::serialize(dt, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn default() -> Option<DateTime<Utc>> {
        None
    }
}

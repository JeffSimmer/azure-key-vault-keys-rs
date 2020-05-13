use http::status::StatusCode;
use keyvault_agent_azure_auth::Credential;
use reqwest::{Client, Method, RequestBuilder, Response};
use serde::de::DeserializeOwned;
use std::sync::Mutex;
use thiserror::Error;

use crate::auth::*;
use crate::models::*;

pub mod auth;
pub mod models;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::error::Error),
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),
    #[error(transparent)]
    AuthenticationError(#[from] keyvault_agent_azure_auth::Error),
    #[error("{}: {}", .0.code, .0.message)]
    KeyVaultError(models::KeyVaultError),
    #[error("{0}")]
    Unknown(String),
}

pub struct KeyClient {
    authenticator: Mutex<KeyVaultAuthenticator>,
    client: Client,
}

impl KeyClient {
    const API_VERSION: &'static str = "7.0";
    pub fn new(cred: Credential) -> KeyClient {
        let client = Client::new();

        KeyClient {
            authenticator: Mutex::new(KeyVaultAuthenticator::new(cred)),
            client,
        }
    }

    pub async fn list_keys(&self, vault_uri: &str) -> Result<Vec<KeyListEntry>> {
        self.list_keys_impl(format!(
            "{vault_uri}/keys?api-version={api_version}",
            vault_uri = &vault_uri,
            api_version = KeyClient::API_VERSION
        ))
        .await
    }

    pub async fn list_key_versions(&self, key_uri: &str) -> Result<Vec<KeyListEntry>> {
        self.list_keys_impl(format!(
            "{key_uri}/versions?api-version={api_version}",
            key_uri = &key_uri,
            api_version = KeyClient::API_VERSION
        ))
        .await
    }

    async fn list_keys_impl(&self, list_uri: String) -> Result<Vec<KeyListEntry>> {
        let mut list_uri = Some(list_uri);
        let mut list_entries = Vec::new();

        while let Some(next_link) = &list_uri {
            let key_list: KeyList = self.request(|c| c.request(Method::GET, next_link)).await?;

            list_entries.push(key_list.value);
            list_uri = key_list.next_link;
        }

        Ok(list_entries.into_iter().flatten().collect())
    }

    pub async fn create_key(
        &self,
        vault_uri: &str,
        options: CreateKeyOptions,
    ) -> Result<KeyVaultKey> {
        self.request(|c| {
            c.post(&format!(
                "{vault_uri}/keys/{key_name}/create?api-version={api_version}",
                vault_uri = &vault_uri,
                key_name = &options.name,
                api_version = KeyClient::API_VERSION
            ))
            .json(&options)
        })
        .await
    }

    pub async fn delete_key(&self, key_uri: &str) -> Result<KeyVaultKey> {
        self.request(|c| {
            c.delete(&format!(
                "{key_uri}?api-version={api_version}",
                key_uri = &key_uri,
                api_version = KeyClient::API_VERSION
            ))
        })
        .await
    }

    pub async fn get_key(&self, key_name: &str) -> Result<KeyVaultKey> {
        self.request(|c| {
            c.request(
                Method::GET,
                &format!(
                    "{key_name}?api-version={api_version}",
                    key_name = &key_name,
                    api_version = KeyClient::API_VERSION
                ),
            )
        })
        .await
    }

    pub async fn sign_digest(
        &self,
        key_name: &str,
        alg: &str,
        value: &[u8],
    ) -> Result<KeyOperationResult> {
        self.request(|c| {
            c.post(&format!(
                "{key_name}/sign?api-version={api_version}",
                key_name = &key_name,
                api_version = KeyClient::API_VERSION
            ))
            .json(&SignRequest {
                alg: alg.to_string(),
                value: value.to_vec(),
            })
        })
        .await
    }

    pub async fn verify_digest(
        &self,
        key_name: &str,
        alg: &str,
        digest: &[u8],
        value: &[u8],
    ) -> Result<bool> {
        let result: VerifyResult = self
            .request(|c| {
                c.post(&format!(
                    "{key_name}/verify?api-version={api_version}",
                    key_name = &key_name,
                    api_version = KeyClient::API_VERSION
                ))
                .json(&VerifyRequest {
                    alg: alg.to_string(),
                    digest: digest.to_vec(),
                    value: value.to_vec(),
                })
            })
            .await?;

        Ok(result.value)
    }

    pub async fn encrypt(
        &self,
        key_name: &str,
        alg: &str,
        value: &[u8],
    ) -> Result<KeyOperationResult> {
        self.request(|c| {
            c.post(&format!(
                "{key_name}/encrypt?api-version={api_version}",
                key_name = &key_name,
                api_version = KeyClient::API_VERSION
            ))
            .json(&EncryptRequest {
                alg: alg.to_string(),
                value: value.to_vec(),
            })
        })
        .await
    }

    pub async fn decrypt(
        &self,
        key_name: &str,
        alg: &str,
        value: &[u8],
    ) -> Result<KeyOperationResult> {
        self.request(|c| {
            c.post(&format!(
                "{key_name}/decrypt?api-version={api_version}",
                key_name = &key_name,
                api_version = KeyClient::API_VERSION
            ))
            .json(&DecryptRequest {
                alg: alg.to_string(),
                value: value.to_vec(),
            })
        })
        .await
    }

    pub async fn wrap(
        &self,
        key_name: &str,
        alg: &str,
        value: &[u8],
    ) -> Result<KeyOperationResult> {
        self.request(|c| {
            c.post(&format!(
                "{key_name}/wrap?api-version={api_version}",
                key_name = &key_name,
                api_version = KeyClient::API_VERSION
            ))
            .json(&WrapRequest {
                alg: alg.to_string(),
                value: value.to_vec(),
            })
        })
        .await
    }

    pub async fn unwrap(
        &self,
        key_name: &str,
        alg: &str,
        value: &[u8],
    ) -> Result<KeyOperationResult> {
        self.request(|c| {
            c.post(&format!(
                "{key_name}/unwrap?api-version={api_version}",
                key_name = &key_name,
                api_version = KeyClient::API_VERSION
            ))
            .json(&UnwrapRequest {
                alg: alg.to_string(),
                value: value.to_vec(),
            })
        })
        .await
    }

    pub async fn backup(&self, key_name: &str) -> Result<Vec<u8>> {
        let backup: Backup = self
            .request(|c| {
                c.post(&format!(
                    "{key_name}/backup?api-version={api_version}",
                    key_name = &key_name,
                    api_version = KeyClient::API_VERSION
                ))
                .json(&())
            })
            .await?;

        Ok(backup.value)
    }

    pub async fn restore(&self, vault_name: &str, value: &[u8]) -> Result<KeyVaultKey> {
        self.request(|c| {
            c.post(&format!(
                "{vault_name}/keys/restore?api-version={api_version}",
                vault_name = &vault_name,
                api_version = KeyClient::API_VERSION
            ))
            .json(&Backup {
                value: value.to_vec(),
            })
        })
        .await
    }

    pub async fn request<F, RespT>(&self, request_builder: F) -> Result<RespT>
    where
        F: Fn(&Client) -> RequestBuilder,
        RespT: DeserializeOwned,
    {
        let mut response = self.request_impl(&request_builder).await?;

        if response.status() == StatusCode::UNAUTHORIZED {
            self.authenticator
                .lock()
                .unwrap()
                .refresh_token(&response)
                .await?;
            response = self.request_impl(&request_builder).await?;
        }

        match response.status().as_u16() {
            200..=299 => Ok(response.json().await?),
            _ => Err(Error::KeyVaultError(
                response.json::<models::KeyVaultErrorMessage>().await?.error,
            )),
        }
    }

    pub async fn request_impl<F>(&self, request_builder: F) -> Result<Response>
    where
        F: Fn(&Client) -> RequestBuilder,
    {
        let req = (request_builder)(&self.client);

        let req = match self.authenticator.lock().unwrap().token() {
            Some(token) => req.bearer_auth(token),
            None => req,
        };

        Ok(req.send().await?)
    }
}

pub struct BearerAuthenticateHeader {
    authorization: String,
    resource: String,
}

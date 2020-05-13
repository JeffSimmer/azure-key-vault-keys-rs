use keyvault_agent_azure_auth::{Authenticator, Credential, TokenRequestOptions};
use quoted_string::test_utils::TestSpec;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{BearerAuthenticateHeader, Error, Result};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TokenResponse {
    pub token_type: String,
    pub access_token: String,
}

pub struct KeyVaultAuthenticator {
    authenticator: Box<dyn Authenticator + Send>,
    token: Option<String>,
}

impl KeyVaultAuthenticator {
    pub fn new(cred: Credential) -> KeyVaultAuthenticator {
        let authenticator = Authenticator::new(cred);
        KeyVaultAuthenticator {
            authenticator,
            token: None,
        }
    }

    pub fn token(&self) -> Option<String> {
        self.token.clone()
    }

    pub async fn refresh_token(&mut self, unauthorized_response: &Response) -> Result<()> {
        let header = unauthorized_response
            .headers()
            .get("WWW-Authenticate")
            .unwrap()
            .to_str()
            .unwrap();

        let auth_header = KeyVaultAuthenticator::parse_refresh_header(header)?;

        self.token = Some(
            self.authenticator
                .authenticate(TokenRequestOptions::from_resource_uri(
                    auth_header.resource.as_str(),
                    auth_header.authorization.as_str(),
                ))
                .await?
                .access_token,
        );

        Ok(())
    }

    fn parse_refresh_header(header: &str) -> Result<BearerAuthenticateHeader> {
        let mut split_header = header.splitn(2, ' ');
        let auth_type = split_header.next().unwrap();
        let params = split_header.next().unwrap();
        let params: HashMap<String, String> = params
            .split(',')
            .map(|param| {
                let mut kvpair = param.trim().split('=');
                (
                    kvpair.next().unwrap().to_ascii_lowercase(),
                    quoted_string::to_content::<TestSpec>(kvpair.next().unwrap())
                        .unwrap()
                        .to_string(),
                )
            })
            .collect();

        match auth_type {
            "Bearer" => Ok(BearerAuthenticateHeader {
                authorization: params.get("authorization").unwrap().to_string(),
                resource: params.get("resource").unwrap().to_string(),
            }),
            _ => Err(Error::Unknown(
                "Unsupported authentication challenge".to_string(),
            )),
        }
    }
}

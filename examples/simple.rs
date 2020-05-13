use keyvault_agent_azure_auth::Credential;
use keyvault_agent_azure_key_vault_keys::models::{CreateKeyOptions, KeyOptions, RsaOptions};
use keyvault_agent_azure_key_vault_keys::KeyClient;
use openssl::hash::{hash, MessageDigest};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let vault_uri = "https://{vault}.vault.azure.net";
    let name = "demokey";
    let key_name = format!("{}/keys/{}", vault_uri, name);
    let credential = Credential::AzureSdk;
    let client = KeyClient::new(credential);

    println!("Creating a key...");
    let key = client
        .create_key(
            vault_uri,
            CreateKeyOptions {
                name: name.to_string(),
                kty: "RSA".to_string(),
                key_options: KeyOptions::Rsa(RsaOptions { key_size: 2048 }),
                key_ops: [
                    "sign",
                    "verify",
                    "wrapKey",
                    "unwrapKey",
                    "encrypt",
                    "decrypt",
                ]
                .iter()
                .map(|o| o.to_string())
                .collect(),
                attributes: None,
                tags: None,
            },
        )
        .await?;
    println!("Key: {}\n", serde_json::to_string(&key)?);

    println!("Backing up the key...");
    let backup = client.backup(&key_name).await?;
    println!("Success!");

    println!("Deleting a key...");
    let key = client.delete_key(&key_name).await?;
    println!("Key: {}\n", serde_json::to_string(&key)?);

    println!("Restoring the key...");
    let key = client.restore(vault_uri, &backup).await?;
    println!("Key: {}\n", serde_json::to_string(&key)?);

    println!("Listing keys...");
    let key_list = client.list_keys(vault_uri).await?;
    println!("Key list: {}\n", serde_json::to_string(&key_list)?);

    println!("Getting a key...");
    let key = client.get_key(&key_name).await?;
    println!("Key: {}\n", serde_json::to_string(&key)?);

    println!("Listing key versions...");
    let key_versions = client.list_key_versions(&key_name).await?;
    println!("Key versions: {}\n", serde_json::to_string(&key_versions)?);

    println!("Sign/Verify");
    let hash = hash(MessageDigest::sha512(), &[1, 3, 2, 4])
        .unwrap()
        .to_vec();
    let result = client.sign_digest(&key_name, "RS512", &hash).await?;
    println!("Sign Result: {}\n", serde_json::to_string(&result)?);
    let result = client
        .verify_digest(&result.kid, "RS512", &hash, &result.value)
        .await?;
    println!("Verify Result: {}\n", result);

    println!("Encrypt/Decrypt");
    let result = client.encrypt(&key_name, "RSA-OAEP", &[1, 3, 2, 4]).await?;
    println!("Encrypt Result: {}\n", serde_json::to_string(&result)?);
    let result = client
        .decrypt(&result.kid, "RSA-OAEP", &result.value)
        .await?;
    println!("Decrypt Result: {}\n", serde_json::to_string(&result)?);

    println!("Wrap/Unwrap");
    let result = client.encrypt(&key_name, "RSA-OAEP", &[1, 3, 2, 4]).await?;
    println!("Encrypt Result: {}\n", serde_json::to_string(&result)?);
    let result = client
        .decrypt(&result.kid, "RSA-OAEP", &result.value)
        .await?;
    println!("Decrypt Result: {}\n", serde_json::to_string(&result)?);

    println!("Deleting a key...");
    let key = client.get_key(&key_name).await?;
    println!("Key: {}\n", serde_json::to_string(&key)?);

    Ok(())
}

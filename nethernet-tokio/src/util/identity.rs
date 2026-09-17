//! Loading the identity a server signs its answers with off the filesystem.

use crate::error::{NetherError, Result};
use nethernet::identity::ServerIdentity;
use std::path::Path;
use std::time::SystemTime;

/// Loads the identity from a PEM private key, creating a P-384 key there on first use.
///
/// The file is never replaced once it exists, because clients pin the public key and a new
/// one prompts every returning player again. On Unix it is created readable only by its
/// owner.
pub async fn from_pem_or_create(
    pem: impl AsRef<Path>,
    domain: impl Into<String>,
) -> Result<ServerIdentity> {
    let pem = pem.as_ref();
    let domain = domain.into();

    match tokio::fs::read_to_string(pem).await {
        Ok(contents) => Ok(ServerIdentity::from_pem(
            &contents,
            domain,
            SystemTime::now(),
        )?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let identity = ServerIdentity::generate(domain, SystemTime::now())?;
            write(pem, &identity.to_pem()?).await?;
            Ok(identity)
        }
        Err(e) => Err(NetherError::Io(e)),
    }
}

/// Loads the identity from a PEM private key that has to exist already.
pub async fn from_pem(pem: impl AsRef<Path>, domain: impl Into<String>) -> Result<ServerIdentity> {
    let contents = tokio::fs::read_to_string(pem.as_ref()).await?;

    Ok(ServerIdentity::from_pem(
        &contents,
        domain,
        SystemTime::now(),
    )?)
}

#[cfg(unix)]
async fn write(path: &Path, pem: &str) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(parent).await?;
    }

    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .await?;

    tokio::io::AsyncWriteExt::write_all(&mut file, pem.as_bytes()).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn write(path: &Path, pem: &str) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(parent).await?;
    }

    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .await?;

    tokio::io::AsyncWriteExt::write_all(&mut file, pem.as_bytes()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_key_is_kept_once_it_exists() {
        let nonce: u64 = rand::random();
        let directory =
            std::env::temp_dir().join(format!("nethernet-pem-{}-{}", std::process::id(), nonce));
        tokio::fs::create_dir(&directory).await.unwrap();
        let pem = directory.join("identity.pem");

        let created = from_pem_or_create(&pem, "example.com").await.unwrap();
        let loaded = from_pem_or_create(&pem, "example.com").await.unwrap();

        assert_eq!(created.verifying_key(), loaded.verifying_key());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = tokio::fs::metadata(&pem)
                .await
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        tokio::fs::remove_dir_all(&directory).await.unwrap();
    }
}

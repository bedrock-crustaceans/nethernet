use crate::error::{ProtocolError, Result};
use aes::Aes256;
use aes::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

const BLOCK_SIZE: usize = 16;

static ENCRYPTION_KEY: LazyLock<[u8; 32]> = LazyLock::new(|| {
    let mut hasher = Sha256::new();
    hasher.update(0xdeadbeef_u64.to_le_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
});

static CIPHER: LazyLock<Aes256> = LazyLock::new(|| Aes256::new((&*ENCRYPTION_KEY).into()));

static HMAC_STATE: LazyLock<Hmac<Sha256>> = LazyLock::new(|| {
    <Hmac<Sha256> as KeyInit>::new_from_slice(ENCRYPTION_KEY.as_slice())
        .expect("HMAC can take key of any size")
});

pub(crate) fn encrypt(buf: &mut Vec<u8>) -> Result<()> {
    let data_len = buf.len();
    let padding_len = BLOCK_SIZE - (data_len % BLOCK_SIZE);
    buf.resize(data_len + padding_len, padding_len as u8);

    let (blocks, _) = Block::<Aes256>::slice_as_chunks_mut(buf.as_mut_slice());
    CIPHER.encrypt_blocks(blocks);

    Ok(())
}

pub(crate) fn decrypt(buf: &mut Vec<u8>) -> Result<()> {
    if buf.is_empty() || !buf.len().is_multiple_of(BLOCK_SIZE) {
        return Err(ProtocolError::Other(
            "Invalid encrypted data length".to_string(),
        ));
    }

    let (blocks, _) = Block::<Aes256>::slice_as_chunks_mut(buf.as_mut_slice());
    CIPHER.decrypt_blocks(blocks);

    let data_len = buf.len();
    if let Some(&padding_len) = buf.last()
        && padding_len > 0
        && padding_len as usize <= BLOCK_SIZE.min(data_len)
    {
        let padding_start = data_len - padding_len as usize;
        let mut mismatched: u8 = 0;
        for &byte in &buf[padding_start..] {
            mismatched |= byte ^ padding_len;
        }
        if mismatched == 0 {
            buf.truncate(padding_start);
            return Ok(());
        }
    }

    Err(ProtocolError::Other("Invalid padding".to_string()))
}

pub(crate) fn compute_checksum(data: &[u8]) -> [u8; 32] {
    let mut mac = HMAC_STATE.clone();
    mac.update(data);
    let result = mac.finalize();
    result.into_bytes().into()
}

pub(crate) fn verify_checksum(data: &[u8], expected: &[u8; 32]) -> bool {
    let mut mac = HMAC_STATE.clone();
    mac.update(data);
    mac.verify_slice(expected).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let data = b"Hello, NetherNet!";
        let mut buf = data.to_vec();
        encrypt(&mut buf).unwrap();
        decrypt(&mut buf).unwrap();
        assert_eq!(data.as_slice(), buf.as_slice());
    }

    #[test]
    fn test_checksum() {
        let data = b"Test data for checksum";
        let checksum = compute_checksum(data);
        assert!(verify_checksum(data, &checksum));

        let wrong_checksum = [0u8; 32];
        assert!(!verify_checksum(data, &wrong_checksum));
    }
}

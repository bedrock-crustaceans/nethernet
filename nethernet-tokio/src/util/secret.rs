//! Secrets a host configured, which may be the value itself or a file holding it.
//!
//! A configuration file is read by anyone who can read the directory, gets copied between
//! machines and ends up in support requests. A file reference keeps the secret out of it
//! and leaves the protection to the filesystem.

use std::io;
use std::path::{Path, PathBuf};

/// Above this a file is something other than a secret, and reading it is a waste.
const MAX_BYTES: u64 = 16384;

/// Resolves a configured value, reading it from a file when it names one.
///
/// A value is a file reference when it begins with `file:` or looks like a path. The
/// trailing line terminator of the file is dropped, because a file written by an editor
/// has one and it is never part of the secret.
pub async fn resolve(value: &str, directory: impl AsRef<Path>) -> io::Result<String> {
    let Some(path) = reference(value, directory.as_ref()) else {
        return Ok(value.to_string());
    };

    let metadata = tokio::fs::metadata(&path).await?;
    if metadata.len() > MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is too large to be a secret", path.display()),
        ));
    }

    let secret = tokio::fs::read_to_string(&path).await?;
    Ok(strip_line_terminator(&secret).to_string())
}

/// The file a value names, or [`None`] when the value is the secret itself.
pub fn reference(value: &str, directory: &Path) -> Option<PathBuf> {
    if let Some(path) = value.strip_prefix("file:") {
        return Some(resolve_against(directory, path));
    }

    let looks_like_a_path = value.contains('/')
        || value.contains('\\')
        || Path::new(value)
            .extension()
            .is_some_and(|extension| !extension.is_empty());

    match looks_like_a_path && !value.contains(char::is_whitespace) {
        true => Some(resolve_against(directory, value)),
        false => None,
    }
}

fn resolve_against(directory: &Path, value: &str) -> PathBuf {
    let path = Path::new(value);
    match path.is_absolute() {
        true => path.to_path_buf(),
        false => directory.join(path),
    }
}

fn strip_line_terminator(value: &str) -> &str {
    value
        .strip_suffix('\n')
        .map(|value| value.strip_suffix('\r').unwrap_or(value))
        .unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_value_is_the_secret_itself() {
        assert!(reference("hunter2", Path::new("/etc")).is_none());
        assert!(reference("a sentence with spaces", Path::new("/etc")).is_none());
    }

    #[test]
    fn a_path_names_a_file() {
        assert_eq!(
            reference("file:secret.txt", Path::new("/etc")),
            Some(PathBuf::from("/etc/secret.txt"))
        );
        assert_eq!(
            reference("keys/secret", Path::new("/etc")),
            Some(PathBuf::from("/etc/keys/secret"))
        );
        assert_eq!(
            reference("/run/secret", Path::new("/etc")),
            Some(PathBuf::from("/run/secret"))
        );
    }

    #[tokio::test]
    async fn a_referenced_file_is_read_without_its_line_terminator() {
        let directory = std::env::temp_dir().join(format!("nethernet-{}", std::process::id()));
        tokio::fs::create_dir_all(&directory).await.unwrap();
        let path = directory.join("secret.txt");
        tokio::fs::write(&path, "hunter2\r\n").await.unwrap();

        assert_eq!(resolve("file:secret.txt", &directory).await.unwrap(), "hunter2");
        assert_eq!(resolve("hunter2", &directory).await.unwrap(), "hunter2");

        tokio::fs::remove_dir_all(&directory).await.unwrap();
    }
}

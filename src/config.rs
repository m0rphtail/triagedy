//! Secret storage for triagedy.
//!
//! An API key never belongs on a command line (visible to other processes),
//! in shell history, or in a repo. `triagedy init` writes it once to
//! `~/.config/triagedy/env` with mode 0600, and the jev backend reads it
//! automatically. Resolution order, first hit wins:
//!
//! 1. `--api-key` flag (kept for scripting; visible to other processes)
//! 2. `$TYPESAFE_API_KEY` (CI / containers)
//! 3. `~/.config/triagedy/env` (written by `triagedy init`)

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

/// Name of the key as stored in the env file and read from the environment.
pub const KEY_NAME: &str = "TYPESAFE_API_KEY";

/// Config directory: `$XDG_CONFIG_HOME/triagedy`, else `~/.config/triagedy`.
pub fn config_dir() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".config"))
        })
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("triagedy")
}

/// Path of the secrets file `triagedy init` writes.
pub fn key_file() -> PathBuf {
    config_dir().join("env")
}

/// Read the key out of a stored env file. Tolerates comments, blank lines,
/// and other variables; returns None when the file or the key is absent.
pub fn load_key_from(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((name, value)) = line.split_once('=')
            && name.trim() == KEY_NAME
        {
            let value = value.trim().trim_matches('"');
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Write the key to `path` with 0600, creating the parent dir with 0700.
/// Permissions are applied even when the file already existed.
pub fn store_key(path: &Path, key: &str) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
        set_private_dir(dir);
    }
    let mut file = open_private(path)?;
    writeln!(
        file,
        "# triagedy secrets — written by `triagedy init`; never commit this file"
    )?;
    writeln!(file, "{KEY_NAME}={key}")?;
    file.flush()?;
    set_private_file(path);
    Ok(())
}

fn open_private(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

#[cfg(unix)]
fn set_private_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn set_private_file(_path: &Path) {}

#[cfg(unix)]
fn set_private_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn set_private_dir(_path: &Path) {}

/// Read a key from the user: hidden prompt on a terminal, otherwise one
/// line from stdin so `printf '%s\n' "$KEY" | triagedy init` works.
pub fn read_key_interactive() -> io::Result<String> {
    if io::stdin().is_terminal() {
        rpassword::prompt_password("Paste your TypeSafe API key (input hidden): ")
    } else {
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        Ok(line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn tmpdir(tag: &str) -> PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!("triagedy-cfg-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn store_then_load_roundtrip() {
        let path = tmpdir("roundtrip").join("env");
        store_key(&path, "abc-123").unwrap();
        assert_eq!(load_key_from(&path).as_deref(), Some("abc-123"));
    }

    #[test]
    fn stored_file_is_0600() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = tmpdir("perms").join("env");
            store_key(&path, "k").unwrap();
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "secret file must not be group/world readable");
        }
    }

    #[test]
    fn overwrite_fixes_loose_permissions() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = tmpdir("loose").join("env");
            fs::write(&path, "old").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            store_key(&path, "k2").unwrap();
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn load_tolerates_comments_and_other_vars() {
        let dir = tmpdir("parse");
        let path = dir.join("env");
        fs::write(&path, "# c\nOTHER=x\nTYPESAFE_API_KEY=zzz\n").unwrap();
        assert_eq!(load_key_from(&path).as_deref(), Some("zzz"));

        fs::write(&path, "OTHER=x\n").unwrap();
        assert_eq!(load_key_from(&path), None);
        assert_eq!(load_key_from(&dir.join("missing")), None);
    }
}

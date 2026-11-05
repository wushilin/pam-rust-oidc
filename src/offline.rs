// Offline logins: while the Auth API cannot be reached, a user whose password
// the Auth API accepted within `offline_days` may log in with that password.
// The MFA answer cannot be checked offline and is ignored.
//
// After every login the Auth API accepts, an Argon2id hash of the password is
// kept in `<working_dir>/offline/<user>` (root only, mode 0600):
//
//     v1 <unix time of the verified login> <Argon2id PHC string>

use super::provision::{private_dir, secure_dir, write_private};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const DAY_SECONDS: u64 = 24 * 60 * 60;
// A cache entry dated later than this is not believed.
const CLOCK_SKEW_SECONDS: u64 = 5 * 60;

fn cache_dir(working_dir: &Path) -> PathBuf {
    working_dir.join("offline")
}

// Only plain Unix names become file names here.
fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= 32
        && bytes
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn trusted_dirs(working_dir: &Path) -> Result<PathBuf, String> {
    let dir = cache_dir(working_dir);
    private_dir(&dir).map_err(|_| "cannot create the offline cache directory")?;
    secure_dir(working_dir)?;
    secure_dir(&dir)?;
    Ok(dir)
}

// 16 bytes from the kernel's random source.
fn random_salt() -> Result<SaltString, String> {
    let mut bytes = [0u8; 16];
    let filled = unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), 0) };
    if filled != bytes.len() as isize {
        return Err("cannot get random bytes for the offline cache".into());
    }
    SaltString::encode_b64(&bytes).map_err(|_| "cannot encode the offline cache salt".into())
}

// Keep the password the Auth API just accepted, replacing what was cached.
pub fn remember(working_dir: &Path, name: &str, password: &[u8], now: u64) -> Result<(), String> {
    if !valid_name(name) {
        return Err("the user name cannot be used for the offline cache".into());
    }
    let dir = trusted_dirs(working_dir)?;
    let salt = random_salt()?;
    let hash = Argon2::default()
        .hash_password(password, &salt)
        .map_err(|_| "cannot hash the password for the offline cache")?;
    write_private(&dir.join(name), &format!("v1 {now} {hash}\n"))
        .map_err(|_| "cannot write the offline cache".into())
}

// When the password was last verified online, if it matches the cached one
// and that is recent enough. Otherwise why there is no offline login.
pub fn check(
    working_dir: &Path,
    name: &str,
    password: &[u8],
    max_age_days: u32,
    now: u64,
) -> Result<u64, &'static str> {
    if !valid_name(name) {
        return Err("no password is cached for this user");
    }
    let dir = cache_dir(working_dir);
    if secure_dir(working_dir).is_err() || secure_dir(&dir).is_err() {
        return Err("the offline cache directory is not trusted");
    }
    let path = dir.join(name);
    let Ok(metadata) = fs::symlink_metadata(&path) else {
        return Err("no password is cached for this user");
    };
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err("the cached password file is not trusted");
    }
    let text = fs::read_to_string(&path).map_err(|_| "cannot read the cached password")?;
    let mut fields = text.trim_end().splitn(3, ' ');
    let (Some("v1"), Some(verified_at), Some(phc)) = (fields.next(), fields.next(), fields.next())
    else {
        return Err("the cached password is malformed");
    };
    let verified_at: u64 = verified_at
        .parse()
        .map_err(|_| "the cached password is malformed")?;
    if verified_at > now + CLOCK_SKEW_SECONDS {
        return Err("the cached password is dated in the future");
    }
    if now.saturating_sub(verified_at) > u64::from(max_age_days) * DAY_SECONDS {
        return Err("the cached password has expired");
    }
    let hash = PasswordHash::new(phc).map_err(|_| "the cached password is malformed")?;
    if hash.algorithm != argon2::Algorithm::Argon2id.ident() {
        return Err("the cached password is malformed");
    }
    Argon2::default()
        .verify_password(password, &hash)
        .map(|()| verified_at)
        .map_err(|_| "the password does not match the cached one")
}

// With offline logins off, no password stays cached.
pub fn forget_all(working_dir: &Path) {
    let dir = cache_dir(working_dir);
    if fs::symlink_metadata(&dir).is_ok() && secure_dir(working_dir).is_ok() {
        if fs::remove_dir_all(&dir).is_ok() {
            super::log("offline logins are off; removed the offline password cache");
        } else {
            super::log(
                "offline logins are off but the offline password cache could not be removed",
            );
        }
    }
}

// "3d 4h", "5h 12m" or "7m".
pub fn age(seconds: u64) -> String {
    let (days, hours, minutes) = (
        seconds / DAY_SECONDS,
        seconds / 3600 % 24,
        seconds / 60 % 60,
    );
    match (days, hours) {
        (0, 0) => format!("{minutes}m"),
        (0, _) => format!("{hours}h {minutes}m"),
        _ => format!("{days}d {hours}h"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> TempDir {
            let path = std::env::temp_dir().join(format!(
                "pam-rust-oidc-offline-{label}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&path);
            TempDir(path)
        }

        fn wd(&self) -> PathBuf {
            self.0.join("wd")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn a_remembered_password_logs_in_until_it_expires() {
        let temp = TempDir::new("remember");
        let wd = temp.wd();
        remember(&wd, "alice", b"correct horse", NOW).unwrap();
        let file = cache_dir(&wd).join("alice");
        assert_eq!(fs::metadata(&file).unwrap().mode() & 0o7777, 0o600);
        assert_eq!(fs::metadata(cache_dir(&wd)).unwrap().mode() & 0o7777, 0o700);
        let text = fs::read_to_string(&file).unwrap();
        assert!(text.starts_with(&format!("v1 {NOW} $argon2id$")), "{text}");
        assert!(!text.contains("correct horse"));

        assert_eq!(check(&wd, "alice", b"correct horse", 7, NOW + 60), Ok(NOW));
        assert_eq!(
            check(&wd, "alice", b"correct horse", 7, NOW + 7 * DAY_SECONDS),
            Ok(NOW)
        );
        assert_eq!(
            check(&wd, "alice", b"correct horse", 7, NOW + 7 * DAY_SECONDS + 1),
            Err("the cached password has expired")
        );
        assert_eq!(
            check(&wd, "alice", b"wrong", 7, NOW + 60),
            Err("the password does not match the cached one")
        );
        assert_eq!(
            check(&wd, "bob", b"correct horse", 7, NOW + 60),
            Err("no password is cached for this user")
        );
        assert_eq!(
            check(
                &wd,
                "alice",
                b"correct horse",
                7,
                NOW - CLOCK_SKEW_SECONDS - 1
            ),
            Err("the cached password is dated in the future")
        );
    }

    #[test]
    fn a_new_login_replaces_the_cached_password() {
        let temp = TempDir::new("replace");
        let wd = temp.wd();
        remember(&wd, "alice", b"old password", NOW).unwrap();
        remember(&wd, "alice", b"new password", NOW + 100).unwrap();
        assert!(check(&wd, "alice", b"old password", 7, NOW + 200).is_err());
        assert_eq!(
            check(&wd, "alice", b"new password", 7, NOW + 200),
            Ok(NOW + 100)
        );
    }

    #[test]
    fn untrusted_or_malformed_files_are_refused() {
        let temp = TempDir::new("untrusted");
        let wd = temp.wd();
        remember(&wd, "alice", b"secret", NOW).unwrap();
        let file = cache_dir(&wd).join("alice");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            check(&wd, "alice", b"secret", 7, NOW),
            Err("the cached password file is not trusted")
        );
        fs::write(&file, "v1 notanumber $argon2id$x\n").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            check(&wd, "alice", b"secret", 7, NOW),
            Err("the cached password is malformed")
        );
        fs::set_permissions(cache_dir(&wd), fs::Permissions::from_mode(0o770)).unwrap();
        assert_eq!(
            check(&wd, "alice", b"secret", 7, NOW),
            Err("the offline cache directory is not trusted")
        );
    }

    #[test]
    fn only_plain_names_are_cached() {
        let temp = TempDir::new("names");
        let wd = temp.wd();
        for name in ["", "../etc", "a/b", ".hidden", "-x", "a b", &"a".repeat(33)] {
            assert!(remember(&wd, name, b"secret", NOW).is_err(), "{name:?}");
            assert!(check(&wd, name, b"secret", 7, NOW).is_err(), "{name:?}");
        }
        for name in ["alice", "Alice.Smith", "user_1", "a-b"] {
            assert!(remember(&wd, name, b"secret", NOW).is_ok(), "{name:?}");
        }
    }

    #[test]
    fn turning_offline_logins_off_removes_the_cache() {
        let temp = TempDir::new("forget");
        let wd = temp.wd();
        remember(&wd, "alice", b"secret", NOW).unwrap();
        forget_all(&wd);
        assert!(!cache_dir(&wd).exists());
        assert_eq!(
            check(&wd, "alice", b"secret", 7, NOW),
            Err("no password is cached for this user")
        );
        forget_all(&wd);
    }

    #[test]
    fn ages_read_naturally() {
        assert_eq!(age(7 * 60), "7m");
        assert_eq!(age(5 * 3600 + 12 * 60), "5h 12m");
        assert_eq!(age(3 * DAY_SECONDS + 4 * 3600 + 59), "3d 4h");
    }
}

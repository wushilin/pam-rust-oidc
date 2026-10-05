//! On-demand Unix accounts and sudo rules for users of the Auth API.
//!
//! sshd hides what an unknown user types, so an account cannot be created and
//! verified in one login. The first attempt for an unknown name creates a
//! *pending* account (no home directory, no sudo, a random password nobody
//! knows) and asks the user to log in again. The first verified login makes
//! it *active*. Pending accounts that are never used are deleted.

use super::{log, lookup_ids, unix_time};
use serde::Deserialize;
use std::fs;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const DEFAULT_WORKING_DIR: &str = "/var/lib/pam_rust_oidc";
const SUDOERS_DIR: &str = "/etc/sudoers.d";
const SUDOERS_HEADER: &str =
    "# Managed by pam_rust_oidc. Do not edit: rewritten or removed at login.";
const TOOL_DIRS: [&str; 4] = ["/usr/sbin", "/sbin", "/usr/bin", "/bin"];
const ACCOUNT_COMMENT: &str = "pam_rust_oidc on-demand account";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provisioning {
    #[serde(default)]
    pub enabled: bool,
    // Everything the module keeps between logins lives under this directory:
    //   accounts/<name>   one state file per account it created
    //   stats/addresses   accounts created per source address
    //   lock              held while any of the above, or an account, changes
    #[serde(default = "default_working_dir")]
    pub working_dir: PathBuf,
    #[serde(default = "default_admin_role")]
    pub admin_role: String,
    #[serde(default = "default_pending_ttl_minutes")]
    pub pending_ttl_minutes: u64,
    #[serde(default = "default_max_pending")]
    pub max_pending: usize,
    // Per source address: this many accounts created within the window
    // suspends creation from that address for the ban time. 0 turns it off.
    #[serde(default = "default_max_creations_per_address")]
    pub max_creations_per_address: u32,
    #[serde(default = "default_sixty")]
    pub creation_window_minutes: u64,
    #[serde(default = "default_sixty")]
    pub creation_ban_minutes: u64,
    #[serde(default = "default_tracked_addresses")]
    pub tracked_addresses: usize,
}

impl Default for Provisioning {
    fn default() -> Self {
        Provisioning {
            enabled: false,
            working_dir: default_working_dir(),
            admin_role: default_admin_role(),
            pending_ttl_minutes: default_pending_ttl_minutes(),
            max_pending: default_max_pending(),
            max_creations_per_address: default_max_creations_per_address(),
            creation_window_minutes: default_sixty(),
            creation_ban_minutes: default_sixty(),
            tracked_addresses: default_tracked_addresses(),
        }
    }
}

fn default_working_dir() -> PathBuf {
    DEFAULT_WORKING_DIR.into()
}

fn default_admin_role() -> String {
    "admin".into()
}

fn default_pending_ttl_minutes() -> u64 {
    2
}

fn default_max_pending() -> usize {
    20
}

fn default_max_creations_per_address() -> u32 {
    10
}

fn default_sixty() -> u64 {
    60
}

fn default_tracked_addresses() -> usize {
    4096
}

// Every login runs the module in its own process, so everything that changes
// accounts or the files below happens under this lock. It is released when
// the value is dropped or the process ends.
struct Lock(#[allow(dead_code)] fs::File);

impl Lock {
    // Also the gate for using the working directory at all.
    fn acquire(working_dir: &Path) -> Result<Lock, String> {
        private_dir(working_dir).map_err(|_| "cannot create the working directory")?;
        for dir in [working_dir.to_owned(), working_dir.join("accounts"), working_dir.join("stats")] {
            secure_dir(&dir)?;
        }
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(working_dir.join("lock"))
            .map_err(|_| "cannot open the lock file")?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err("cannot lock the account state".into());
        }
        Ok(Lock(file))
    }
}

// Make sure a directory of ours can be trusted, if it exists. It must be a
// real directory owned by the user the module runs as (root). If group or
// others could only look into it, that is corrected and it is used. If they
// could write to it, what is in it cannot be trusted and it is refused.
fn secure_dir(path: &Path) -> Result<(), String> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    let name = path.display();
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(format!("{name} must be a directory owned by root"));
    }
    let mode = metadata.mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(format!(
            "{name} was writable by other users (mode {mode:04o}); check its content and set mode 0700"
        ));
    }
    if mode != 0o700 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| format!("cannot set mode 0700 on {name}"))?;
        log(&format!("corrected the mode of {name} from {mode:04o} to 0700"));
    }
    Ok(())
}

// Create a root-only directory (and its parents) if it is not there yet.
fn private_dir(path: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new().recursive(true).mode(0o700).create(path)
}

// The key a source address is counted under. `None` for addresses that are
// never limited: loopback (local testing) and anything that is not usable.
fn counted_address(address: &str) -> Option<String> {
    let address = address.trim();
    if address.is_empty()
        || address.len() > 64
        || address.bytes().any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return None;
    }
    match address.parse::<IpAddr>() {
        Ok(ip) if ip.to_canonical().is_loopback() => None,
        Ok(ip) => Some(ip.to_canonical().to_string()),
        Err(_) if address.eq_ignore_ascii_case("localhost") => None,
        Err(_) => Some(address.to_ascii_lowercase()),
    }
}

#[derive(Debug, PartialEq)]
struct AddressEntry {
    address: String,
    window_start: u64,
    count: u32,
    banned_until: u64,
    last_seen: u64,
}

// How many accounts each source address created recently.
#[derive(Default)]
struct AddressTable(Vec<AddressEntry>);

impl AddressTable {
    fn parse(text: &str) -> AddressTable {
        AddressTable(
            text.lines()
                .filter_map(|line| {
                    let mut fields = line.split_whitespace();
                    Some(AddressEntry {
                        address: fields.next()?.to_owned(),
                        window_start: fields.next()?.parse().ok()?,
                        count: fields.next()?.parse().ok()?,
                        banned_until: fields.next()?.parse().ok()?,
                        last_seen: fields.next()?.parse().ok()?,
                    })
                })
                .collect(),
        )
    }

    // Least recently seen entries are dropped beyond `limit`.
    fn serialize(&mut self, limit: usize) -> String {
        self.0.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        self.0.truncate(limit);
        self.0
            .iter()
            .map(|entry| {
                format!(
                    "{} {} {} {} {}\n",
                    entry.address,
                    entry.window_start,
                    entry.count,
                    entry.banned_until,
                    entry.last_seen
                )
            })
            .collect()
    }

    fn banned(&self, address: &str, now: u64) -> bool {
        self.0
            .iter()
            .any(|entry| entry.address == address && entry.banned_until > now)
    }

    // Count one created account. True if this starts a ban.
    fn record(&mut self, address: &str, now: u64, limits: &Provisioning) -> bool {
        let position = self.0.iter().position(|entry| entry.address == address);
        let entry = match position {
            Some(index) => &mut self.0[index],
            None => {
                self.0.push(AddressEntry {
                    address: address.to_owned(),
                    window_start: now,
                    count: 0,
                    banned_until: 0,
                    last_seen: now,
                });
                self.0.last_mut().expect("just pushed")
            }
        };
        if now.saturating_sub(entry.window_start) >= limits.creation_window_minutes * 60 {
            entry.window_start = now;
            entry.count = 0;
        }
        entry.count += 1;
        entry.last_seen = now;
        if entry.count < limits.max_creations_per_address {
            return false;
        }
        entry.banned_until = now + limits.creation_ban_minutes * 60;
        entry.window_start = now;
        entry.count = 0;
        true
    }
}

#[derive(Debug, PartialEq)]
enum AccountState {
    Pending(u64),
    Active,
}

fn parse_state(text: &str) -> Option<AccountState> {
    let mut words = text.split_whitespace();
    match (words.next()?, words.next()?.parse::<u64>().ok()?) {
        ("pending", since) => Some(AccountState::Pending(since)),
        ("active", _) => Some(AccountState::Active),
        _ => None,
    }
}

// Names this module will create accounts and sudoers files for. No dots:
// sudo ignores files in sudoers.d whose name contains one.
pub fn valid_new_username(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= 32
        && bytes
            .next()
            .is_some_and(|first| first.is_ascii_lowercase() || first == b'_')
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
}

// A well-formed SHA-512 crypt entry whose salt and digest are random. Nobody,
// including this module, knows a password that hashes to it.
fn unknowable_password_hash() -> Option<String> {
    const ALPHABET: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut random = [0u8; 16 + 86];
    fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut random))
        .ok()?;
    let mut text: Vec<u8> = random.iter().map(|byte| ALPHABET[(byte & 63) as usize]).collect();
    // The last digest character only carries two bits.
    text[16 + 85] = ALPHABET[(random[16 + 85] & 3) as usize];
    let (salt, digest) = text.split_at(16);
    Some(format!(
        "$6${}${}",
        String::from_utf8_lossy(salt),
        String::from_utf8_lossy(digest)
    ))
}

fn sudoers_content(name: &str) -> String {
    // sudo asks for a password; with this module in sudo's PAM stack that is
    // the user's Auth API password and MFA code.
    format!("{SUDOERS_HEADER}\n{name} ALL=(ALL:ALL) ALL\n")
}

// The host process may ignore or handle SIGCHLD, which breaks waiting for a
// child. Restore the default while a helper runs, as pam_unix does.
struct DefaultSigchld(libc::sigaction);

impl DefaultSigchld {
    fn new() -> Self {
        unsafe {
            let mut previous: libc::sigaction = std::mem::zeroed();
            let mut default: libc::sigaction = std::mem::zeroed();
            default.sa_sigaction = libc::SIG_DFL;
            libc::sigaction(libc::SIGCHLD, &default, &mut previous);
            DefaultSigchld(previous)
        }
    }
}

impl Drop for DefaultSigchld {
    fn drop(&mut self) {
        unsafe {
            libc::sigaction(libc::SIGCHLD, &self.0, std::ptr::null_mut());
        }
    }
}

// Run a system tool with a clean environment. `None` if it is not installed.
fn run(tool: &str, args: &[&str], input: Option<&[u8]>) -> Option<bool> {
    let program = TOOL_DIRS
        .iter()
        .map(|dir| Path::new(dir).join(tool))
        .find(|path| path.is_file())?;
    let _sigchld = DefaultSigchld::new();
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", TOOL_DIRS.join(":"))
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    if let (Some(input), Some(mut stdin)) = (input, child.stdin.take()) {
        let _ = stdin.write_all(input);
    }
    Some(child.wait().is_ok_and(|status| status.success()))
}

// Replace a root-only file in one step, so a reader never sees half of it.
fn write_private(path: &Path, content: &str) -> std::io::Result<()> {
    let temporary = path.with_extension("tmp");
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)
        .and_then(|mut file| file.write_all(content.as_bytes()))?;
    fs::rename(&temporary, path)
}

// The sudoers file for `name`, but only if this module wrote it.
fn managed_sudoers(name: &str) -> Option<PathBuf> {
    let path = Path::new(SUDOERS_DIR).join(name);
    fs::read_to_string(&path)
        .ok()
        .filter(|text| text.starts_with(SUDOERS_HEADER))
        .map(|_| path)
}

impl Provisioning {
    pub fn validate(&self) -> Result<(), String> {
        if !self.working_dir.is_absolute()
            || self
                .working_dir
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err("provisioning.working_dir must be absolute and cannot contain '..'".into());
        }
        Ok(())
    }

    fn accounts_dir(&self) -> PathBuf {
        self.working_dir.join("accounts")
    }

    fn addresses_file(&self) -> PathBuf {
        self.working_dir.join("stats").join("addresses")
    }

    fn state_path(&self, name: &str) -> PathBuf {
        self.accounts_dir().join(name)
    }

    // State is only believed from a regular file that root owns and nobody
    // else can write: it decides which accounts may be deleted.
    fn read_state(&self, name: &str) -> Option<AccountState> {
        let path = self.state_path(name);
        let metadata = fs::symlink_metadata(&path).ok()?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o022 != 0
        {
            return None;
        }
        parse_state(&fs::read_to_string(path).ok()?)
    }

    fn write_state(&self, name: &str, state: &str, now: u64) -> Result<(), String> {
        private_dir(&self.accounts_dir())
            .and_then(|()| write_private(&self.state_path(name), &format!("{state} {now}\n")))
            .map_err(|_| "cannot write account state".into())
    }

    fn load_addresses(&self) -> AddressTable {
        AddressTable::parse(&fs::read_to_string(self.addresses_file()).unwrap_or_default())
    }

    fn save_addresses(&self, addresses: &mut AddressTable) -> std::io::Result<()> {
        private_dir(&self.working_dir.join("stats"))?;
        write_private(&self.addresses_file(), &addresses.serialize(self.tracked_addresses))
    }

    // Called for every login attempt: remove stale pending accounts and, for a
    // name the host does not know, create one. True if an account was created.
    pub fn on_attempt(
        &self,
        name: &str,
        address: Option<&str>,
        min_uid: libc::uid_t,
        local_users: &[String],
    ) -> bool {
        let _lock = match Lock::acquire(&self.working_dir) {
            Ok(lock) => lock,
            Err(message) => {
                log(&format!("{message}; no account is created"));
                return false;
            }
        };
        self.cleanup(name, min_uid, local_users);
        if lookup_ids(name).is_some()
            || local_users.iter().any(|local| local.eq_ignore_ascii_case(name))
        {
            return false;
        }
        let address = address
            .and_then(counted_address)
            .filter(|_| self.max_creations_per_address > 0);
        let mut addresses = self.load_addresses();
        let Ok(now) = unix_time() else {
            return false;
        };
        if address.as_deref().is_some_and(|address| addresses.banned(address, now)) {
            return false;
        }
        match self.create_pending(name) {
            Ok(true) => {
                if let Some(address) = &address {
                    if addresses.record(address, now, self) {
                        log(&format!(
                            "{address} created {} accounts; no more from it for {} minutes",
                            self.max_creations_per_address, self.creation_ban_minutes
                        ));
                    }
                    if self.save_addresses(&mut addresses).is_err() {
                        log("cannot write the address statistics");
                    }
                }
                true
            }
            Ok(false) => false,
            Err(message) => {
                log(&format!("account not created: {message}"));
                false
            }
        }
    }

    fn pending_accounts(&self) -> Vec<(String, u64)> {
        let Ok(entries) = fs::read_dir(self.accounts_dir()) else {
            return Vec::new();
        };
        entries
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .filter(|name| valid_new_username(name))
            .filter_map(|name| match self.read_state(&name)? {
                AccountState::Pending(since) => Some((name, since)),
                AccountState::Active => None,
            })
            .collect()
    }

    // Delete pending accounts nobody completed a login for. The account now
    // logging in is kept: its owner may be typing their password.
    fn cleanup(&self, current: &str, min_uid: libc::uid_t, local_users: &[String]) {
        let Ok(now) = unix_time() else {
            return;
        };
        for (name, since) in self.pending_accounts() {
            if now.saturating_sub(since) < self.pending_ttl_minutes * 60
                || name == current
                || !valid_new_username(&name)
                || local_users.iter().any(|local| local.eq_ignore_ascii_case(&name))
            {
                continue;
            }
            let removed = match lookup_ids(&name) {
                None => true,
                Some((uid, _)) if uid >= min_uid => run("userdel", &[&name], None) == Some(true),
                Some(_) => false,
            };
            if removed {
                if let Some(path) = managed_sudoers(&name) {
                    let _ = fs::remove_file(path);
                }
                let _ = fs::remove_file(self.state_path(&name));
                log(&format!("removed unused pending account {name:?}"));
            }
        }
    }

    // Create a pending account for a name the host does not know. `Ok(false)`
    // means the name is not one this module creates accounts for.
    fn create_pending(&self, name: &str) -> Result<bool, String> {
        if !valid_new_username(name) {
            return Ok(false);
        }
        if self.pending_accounts().len() >= self.max_pending {
            return Err("too many pending accounts".into());
        }
        let now = unix_time()?;
        // Recorded first, so a half-created account is still cleaned up.
        self.write_state(name, "pending", now)?;
        // The account gets a password nobody knows: a password hash made of
        // random characters, so no password exists that matches it. It is only
        // usable through the Auth API. (Set by useradd itself; a separate
        // chpasswd is not allowed from sshd under SELinux.)
        let Some(hash) = unknowable_password_hash() else {
            let _ = fs::remove_file(self.state_path(name));
            return Err("no random data for the new account's password".into());
        };
        let arguments = ["-M", "-s", "/bin/bash", "-c", ACCOUNT_COMMENT, "-p", &hash, name];
        if run("useradd", &arguments, None) != Some(true) {
            let _ = fs::remove_file(self.state_path(name));
            return Err("useradd failed".into());
        }
        log(&format!("created pending account {name:?}"));
        Ok(true)
    }

    // After the Auth API verified `name`: activate a pending account and bring
    // its sudo rule in line with its roles. Only accounts this module created
    // are managed; one an administrator made keeps whatever sudo it was given.
    pub fn on_verified(&self, name: &str, roles: &[String]) {
        let _lock = match Lock::acquire(&self.working_dir) {
            Ok(lock) => lock,
            Err(message) => {
                log(&format!("{message}; the account is left as it is"));
                return;
            }
        };
        if self.read_state(name).is_some_and(|state| state != AccountState::Active) {
            if let Ok(now) = unix_time() {
                let _ = self.write_state(name, "active", now);
            }
            if run("mkhomedir_helper", &[name, "0077"], None) != Some(true) {
                log(&format!("could not create a home directory for {name:?}"));
            }
            log(&format!("account {name:?} is now active"));
        }
        if !valid_new_username(name) || self.read_state(name).is_none() {
            return;
        }
        let path = Path::new(SUDOERS_DIR).join(name);
        let existing = fs::read_to_string(&path).ok();
        if existing
            .as_deref()
            .is_some_and(|text| !text.starts_with(SUDOERS_HEADER))
        {
            // Written by an administrator: never touched.
            return;
        }
        let wanted = roles.iter().any(|role| role == &self.admin_role);
        let content = sudoers_content(name);
        if wanted && existing.as_deref() != Some(&content) {
            // sudo ignores names containing a dot, so the temporary file is inert.
            let temporary = Path::new(SUDOERS_DIR).join(format!(".{name}.tmp"));
            let written = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o440)
                .open(&temporary)
                .and_then(|mut file| file.write_all(content.as_bytes()))
                .is_ok();
            let checked = written
                && temporary
                    .to_str()
                    .is_some_and(|file| run("visudo", &["-cf", file], None) != Some(false));
            if checked && fs::rename(&temporary, &path).is_ok() {
                log(&format!("granted sudo to {name:?} (role {:?})", self.admin_role));
            } else {
                let _ = fs::remove_file(&temporary);
                log(&format!("could not write the sudo rule for {name:?}"));
            }
        } else if !wanted && existing.is_some() && fs::remove_file(&path).is_ok() {
            log(&format!("removed sudo from {name:?}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // A working directory of its own for one test, removed afterwards.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> TempDir {
            let path = std::env::temp_dir().join(format!(
                "pam-rust-oidc-{label}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&path);
            TempDir(path)
        }

        fn provisioning(&self) -> Provisioning {
            Provisioning {
                working_dir: self.0.join("wd"),
                ..Provisioning::default()
            }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn working_directory_layout() {
        let scratch = TempDir::new("layout");
        let provisioning = scratch.provisioning();
        let wd = &provisioning.working_dir;
        assert!(!wd.exists(), "nothing is created until it is needed");

        provisioning.write_state("wutest", "pending", 100).unwrap();
        let mut addresses = AddressTable::default();
        addresses.record("203.0.113.9", 100, &provisioning);
        provisioning.save_addresses(&mut addresses).unwrap();
        drop(Lock::acquire(wd).expect("lock"));

        assert_eq!(fs::read_to_string(wd.join("accounts/wutest")).unwrap(), "pending 100\n");
        assert_eq!(
            fs::read_to_string(wd.join("stats/addresses")).unwrap(),
            "203.0.113.9 100 1 0 100\n"
        );
        assert!(wd.join("lock").is_file());
        for dir in [wd.clone(), wd.join("accounts"), wd.join("stats")] {
            assert_eq!(mode(&dir), 0o700, "{dir:?}");
        }
        for file in ["accounts/wutest", "stats/addresses", "lock"] {
            assert_eq!(mode(&wd.join(file)), 0o600, "{file}");
        }
        assert_eq!(provisioning.load_addresses().0, addresses.0);
    }

    #[test]
    fn account_state_files() {
        let scratch = TempDir::new("state");
        let provisioning = scratch.provisioning();
        assert_eq!(provisioning.read_state("alice"), None);
        assert!(provisioning.pending_accounts().is_empty());

        provisioning.write_state("alice", "pending", 100).unwrap();
        provisioning.write_state("bob", "pending", 200).unwrap();
        provisioning.write_state("carol", "active", 300).unwrap();
        // Not account state: ignored.
        fs::write(provisioning.accounts_dir().join("alice.tmp"), "pending 1\n").unwrap();
        fs::write(provisioning.accounts_dir().join("broken"), "nonsense\n").unwrap();

        assert_eq!(provisioning.read_state("alice"), Some(AccountState::Pending(100)));
        assert_eq!(provisioning.read_state("carol"), Some(AccountState::Active));
        let mut pending = provisioning.pending_accounts();
        pending.sort();
        assert_eq!(pending, [("alice".to_string(), 100), ("bob".to_string(), 200)]);

        provisioning.write_state("alice", "active", 400).unwrap();
        assert_eq!(provisioning.read_state("alice"), Some(AccountState::Active));
        assert_eq!(provisioning.pending_accounts(), [("bob".to_string(), 200)]);
    }

    #[test]
    fn address_statistics_persist_between_logins() {
        let scratch = TempDir::new("stats");
        let provisioning = Provisioning {
            max_creations_per_address: 2,
            ..scratch.provisioning()
        };
        // Each login is a new process: load, change, save.
        for (now, starts_ban) in [(1000, false), (1001, true)] {
            let mut addresses = provisioning.load_addresses();
            assert!(!addresses.banned("203.0.113.9", now));
            assert_eq!(addresses.record("203.0.113.9", now, &provisioning), starts_ban);
            provisioning.save_addresses(&mut addresses).unwrap();
        }
        let addresses = provisioning.load_addresses();
        assert!(addresses.banned("203.0.113.9", 1002));
        assert!(!addresses.banned("203.0.113.9", 1001 + 3600));
    }

    #[test]
    fn the_lock_serialises_concurrent_logins() {
        let scratch = TempDir::new("lock");
        let wd = scratch.0.join("wd");
        let counter = scratch.0.join("counter");
        fs::create_dir_all(&scratch.0).unwrap();
        fs::write(&counter, "0").unwrap();
        // Read, wait, write back: without the lock, updates are lost.
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let (wd, counter) = (wd.clone(), counter.clone());
                std::thread::spawn(move || {
                    for _ in 0..20 {
                        let _lock = Lock::acquire(&wd).expect("lock");
                        let value: u32 = fs::read_to_string(&counter).unwrap().parse().unwrap();
                        std::thread::yield_now();
                        fs::write(&counter, (value + 1).to_string()).unwrap();
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(fs::read_to_string(&counter).unwrap(), "160");
    }

    #[test]
    fn a_readable_working_directory_is_corrected() {
        let scratch = TempDir::new("fix");
        let provisioning = scratch.provisioning();
        let wd = provisioning.working_dir.clone();
        provisioning.write_state("alice", "pending", 100).unwrap();
        for (dir, loose) in [(wd.clone(), 0o755), (wd.join("accounts"), 0o750), (wd.clone(), 0o500)] {
            fs::set_permissions(&dir, fs::Permissions::from_mode(loose)).unwrap();
            assert!(Lock::acquire(&wd).is_ok(), "{dir:?} {loose:o}");
            assert_eq!(mode(&dir), 0o700, "{dir:?} corrected from {loose:o}");
        }
        assert_eq!(provisioning.read_state("alice"), Some(AccountState::Pending(100)));
    }

    #[test]
    fn a_writable_working_directory_is_refused() {
        let scratch = TempDir::new("perms");
        let provisioning = scratch.provisioning();
        let wd = provisioning.working_dir.clone();
        provisioning.write_state("alice", "pending", 100).unwrap();
        for (dir, loose) in [(wd.clone(), 0o777), (wd.clone(), 0o775), (wd.join("accounts"), 0o702)] {
            fs::set_permissions(&dir, fs::Permissions::from_mode(loose)).unwrap();
            assert!(Lock::acquire(&wd).is_err(), "{dir:?} {loose:o}");
            assert_eq!(mode(&dir), loose, "left as found");
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        assert!(Lock::acquire(&wd).is_ok());

        let link = scratch.0.join("link");
        std::os::unix::fs::symlink(&wd, &link).unwrap();
        assert!(Lock::acquire(&link).is_err(), "a symlink is not accepted");
    }

    #[test]
    fn state_files_others_could_write_are_not_believed() {
        let scratch = TempDir::new("statefile");
        let provisioning = scratch.provisioning();
        provisioning.write_state("alice", "pending", 100).unwrap();
        let file = provisioning.state_path("alice");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(provisioning.read_state("alice"), None);
        assert!(provisioning.pending_accounts().is_empty());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(provisioning.read_state("alice"), Some(AccountState::Pending(100)));

        let target = scratch.0.join("elsewhere");
        fs::write(&target, "pending 1\n").unwrap();
        std::os::unix::fs::symlink(&target, provisioning.state_path("bob")).unwrap();
        assert_eq!(provisioning.read_state("bob"), None, "a symlink is not believed");
    }

    #[test]
    fn working_dir_must_be_absolute() {
        let with = |dir: &str| Provisioning {
            working_dir: dir.into(),
            ..Provisioning::default()
        };
        assert!(Provisioning::default().validate().is_ok());
        assert_eq!(Provisioning::default().working_dir, Path::new("/var/lib/pam_rust_oidc"));
        assert!(with("/srv/oidc").validate().is_ok());
        for bad in ["relative/dir", "", "/var/lib/../etc"] {
            assert!(with(bad).validate().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn new_usernames_are_strict() {
        for name in ["wutest", "_svc", "a", "john-doe_2", &"a".repeat(32)] {
            assert!(valid_new_username(name), "{name:?}");
        }
        for name in [
            "",
            "John",
            "john.doe",
            "1abc",
            "-abc",
            "a b",
            "a/b",
            "user@example.net",
            "root\n",
            &"a".repeat(33),
        ] {
            assert!(!valid_new_username(name), "{name:?}");
        }
    }

    #[test]
    fn the_password_hash_is_well_formed_and_random() {
        let hash = unknowable_password_hash().unwrap();
        let parts: Vec<&str> = hash.split('$').collect();
        assert_eq!((parts[0], parts[1]), ("", "6"));
        assert_eq!((parts[2].len(), parts[3].len()), (16, 86));
        let valid = |text: &str| text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'/');
        assert!(valid(parts[2]) && valid(parts[3]));
        assert!("./01".contains(parts[3].chars().last().unwrap()));
        assert_ne!(hash, unknowable_password_hash().unwrap());
    }

    #[test]
    fn parses_account_state() {
        assert_eq!(parse_state("pending 1700000000\n"), Some(AccountState::Pending(1700000000)));
        assert_eq!(parse_state("active 1700000000\n"), Some(AccountState::Active));
        for text in ["", "pending", "pending soon", "deleted 1"] {
            assert_eq!(parse_state(text), None, "{text:?}");
        }
    }

    #[test]
    fn sudoers_rule_is_marked_as_managed() {
        let content = sudoers_content("wutest");
        assert!(content.starts_with(SUDOERS_HEADER));
        assert!(content.ends_with("\nwutest ALL=(ALL:ALL) ALL\n"));
    }

    // Exercises the real system tools. Run as root on a disposable host:
    //   cargo test -- --ignored live_account_lifecycle
    #[test]
    #[ignore = "creates and deletes a real account; needs root"]
    fn live_account_lifecycle() {
        let scratch = TempDir::new("live");
        let provisioning = Provisioning {
            working_dir: scratch.0.clone(),
            ..Provisioning::default()
        };
        let name = format!("oidc-selftest-{}", std::process::id() % 100000);
        let sudoers = Path::new(SUDOERS_DIR).join(&name);
        let home = Path::new("/home").join(&name);

        assert_eq!(provisioning.create_pending(&name), Ok(true));
        let (uid, _) = lookup_ids(&name).expect("account exists");
        let shadow = fs::read_to_string("/etc/shadow").unwrap();
        let entry = shadow.lines().find(|line| line.starts_with(&format!("{name}:"))).unwrap();
        assert!(entry.split(':').nth(1).unwrap().starts_with("$6$"), "a password hash is set");
        assert!(matches!(provisioning.read_state(&name), Some(AccountState::Pending(_))));
        assert!(!home.exists() && !sudoers.exists());

        // Created through the same entry point a login uses. Loopback is not
        // counted, so repeated test runs are never banned.
        assert!(!provisioning.on_attempt(&name, Some("127.0.0.1"), uid, &[]), "already exists");
        provisioning.on_verified(&name, &["admin".to_string()]);
        assert_eq!(provisioning.read_state(&name), Some(AccountState::Active));
        assert!(home.is_dir());
        assert_eq!(fs::read_to_string(&sudoers).unwrap(), sudoers_content(&name));
        assert_eq!(run("visudo", &["-c"], None), Some(true));

        provisioning.on_verified(&name, &["reader".to_string()]);
        assert!(!sudoers.exists(), "sudo rule removed with the role");

        fs::write(&sudoers, format!("{name} ALL=(ALL) ALL\n")).unwrap();
        provisioning.on_verified(&name, &[]);
        assert!(sudoers.exists(), "hand-written rule left alone");
        provisioning.on_verified(&name, &["admin".to_string()]);
        assert!(!fs::read_to_string(&sudoers).unwrap().starts_with(SUDOERS_HEADER));
        fs::remove_file(&sudoers).unwrap();

        // An account the module did not create gets no sudo rule from it.
        let unmanaged = Provisioning {
            working_dir: scratch.0.join("other"),
            ..Provisioning::default()
        };
        unmanaged.on_verified(&name, &["admin".to_string()]);
        assert!(!sudoers.exists(), "unmanaged account is left alone");

        // An active account is never cleaned up; an old pending one is.
        provisioning.cleanup("", uid, &[]);
        assert!(lookup_ids(&name).is_some());
        provisioning.write_state(&name, "pending", 1).unwrap();
        provisioning.cleanup("", uid + 1, &[]);
        assert!(lookup_ids(&name).is_some(), "below min_uid is never deleted");
        provisioning.cleanup("", uid, &[name.clone()]);
        assert!(lookup_ids(&name).is_some(), "local_users are never deleted");
        provisioning.cleanup(&name, uid, &[]);
        assert!(lookup_ids(&name).is_some(), "the account logging in is kept");
        provisioning.cleanup("", uid, &[]);
        assert!(lookup_ids(&name).is_none() && provisioning.read_state(&name).is_none());
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn loopback_addresses_are_not_counted() {
        for local in ["127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1", "localhost", "", "a b"] {
            assert_eq!(counted_address(local), None, "{local:?}");
        }
        assert_eq!(counted_address("203.0.113.9").as_deref(), Some("203.0.113.9"));
        assert_eq!(counted_address("::ffff:203.0.113.9").as_deref(), Some("203.0.113.9"));
        assert_eq!(counted_address("2001:DB8::1").as_deref(), Some("2001:db8::1"));
        assert_eq!(counted_address("Host.Example.NET").as_deref(), Some("host.example.net"));
    }

    #[test]
    fn an_address_is_banned_after_too_many_accounts() {
        let limits = Provisioning {
            max_creations_per_address: 3,
            creation_window_minutes: 10,
            creation_ban_minutes: 60,
            ..Provisioning::default()
        };
        let mut table = AddressTable::default();
        assert!(!table.record("203.0.113.9", 1000, &limits));
        assert!(!table.record("203.0.113.9", 1001, &limits));
        assert!(!table.banned("203.0.113.9", 1002));
        assert!(table.record("203.0.113.9", 1002, &limits), "third account starts the ban");
        assert!(table.banned("203.0.113.9", 1003));
        assert!(!table.banned("198.51.100.7", 1003), "other addresses are unaffected");
        assert!(table.banned("203.0.113.9", 1002 + 3599));
        assert!(!table.banned("203.0.113.9", 1002 + 3600), "the ban ends");
    }

    #[test]
    fn the_count_starts_again_after_the_window() {
        let limits = Provisioning {
            max_creations_per_address: 3,
            creation_window_minutes: 10,
            ..Provisioning::default()
        };
        let mut table = AddressTable::default();
        assert!(!table.record("203.0.113.9", 1000, &limits));
        assert!(!table.record("203.0.113.9", 1001, &limits));
        assert!(!table.record("203.0.113.9", 1000 + 600, &limits), "new window, count is 1");
        assert!(!table.record("203.0.113.9", 1000 + 601, &limits));
        assert!(table.record("203.0.113.9", 1000 + 602, &limits));
    }

    #[test]
    fn address_table_round_trips_and_drops_the_least_recent() {
        let limits = Provisioning::default();
        let mut table = AddressTable::default();
        for (index, address) in ["a", "b", "c"].iter().enumerate() {
            table.record(address, 100 + index as u64, &limits);
        }
        let text = table.serialize(2);
        assert_eq!(text, "c 102 1 0 102\nb 101 1 0 101\n");
        assert_eq!(AddressTable::parse(&text).0, table.0);
        assert!(AddressTable::parse("garbage\n1 2\n").0.is_empty());
    }

    #[test]
    fn provisioning_is_off_by_default() {
        let defaults = Provisioning::default();
        assert!(!defaults.enabled);
        assert_eq!(defaults.admin_role, "admin");
        assert_eq!(defaults.pending_ttl_minutes, 2);
    }
}

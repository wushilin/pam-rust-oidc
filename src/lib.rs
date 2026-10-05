use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::blocking::Client;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::ptr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use x509_parser::pem::parse_x509_pem;
use zeroize::{Zeroize, Zeroizing};

const PAM_SUCCESS: libc::c_int = 0;
const PAM_SERVICE_ERR: libc::c_int = 3;
const PAM_AUTH_ERR: libc::c_int = 7;
const PAM_IGNORE: libc::c_int = 25;
const PAM_CONV_ITEM: libc::c_int = 5;
const PAM_AUTHTOK_ITEM: libc::c_int = 6;
const PAM_PROMPT_ECHO_OFF: libc::c_int = 1;
const DEFAULT_MIN_UID: libc::uid_t = 1000;
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const SUDOERS_PATH: &str = "/etc/sudoers";
const MAX_SUDOERS_DEPTH: u8 = 4;

#[repr(C)]
struct PamMessage {
    msg_style: libc::c_int,
    msg: *const libc::c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut libc::c_char,
    resp_retcode: libc::c_int,
}

#[repr(C)]
struct PamConv {
    conv: Option<
        unsafe extern "C" fn(
            libc::c_int,
            *mut *const PamMessage,
            *mut *mut PamResponse,
            *mut libc::c_void,
        ) -> libc::c_int,
    >,
    appdata_ptr: *mut libc::c_void,
}

#[link(name = "pam")]
extern "C" {
    fn pam_get_user(
        pamh: *mut libc::c_void,
        user: *mut *const libc::c_char,
        prompt: *const libc::c_char,
    ) -> libc::c_int;
    fn pam_get_item(
        pamh: *mut libc::c_void,
        item_type: libc::c_int,
        item: *mut *const libc::c_void,
    ) -> libc::c_int;
    fn pam_set_item(
        pamh: *mut libc::c_void,
        item_type: libc::c_int,
        item: *const libc::c_void,
    ) -> libc::c_int;
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    endpoint: String,
    tenant: String,
    user_domain: String,
    client_id: String,
    api_scope: String,
    #[serde(default)]
    local_users: Vec<String>,
    #[serde(default = "default_min_uid")]
    min_uid: libc::uid_t,
    #[serde(default)]
    api_cert_pin_sha256: CertPins,
    api_ca_file: Option<PathBuf>,
    #[serde(default)]
    api_tls_insecure_trust_all: bool,
    client_auth: ClientAuth,
}

// One fingerprint or a list of them, so the next certificate can be pinned
// before the server rotates to it.
#[derive(Deserialize)]
#[serde(untagged)]
enum CertPins {
    One(String),
    Many(Vec<String>),
}

impl Default for CertPins {
    fn default() -> Self {
        CertPins::Many(Vec::new())
    }
}

// How the Auth API server certificate is trusted. Only the first setting
// present is used: pinned fingerprints, then a CA file, then trust-all, then
// the built-in public roots.
enum ApiTrust<'a> {
    Pinned(Vec<[u8; 32]>),
    CaFile(&'a Path),
    InsecureTrustAll,
    PublicRoots,
}

// Accepts a server certificate by its SHA-256 fingerprint instead of a CA
// chain; with no pins it accepts any certificate. The handshake signature is
// still verified, so the server must hold the certificate's private key.
#[derive(Debug)]
struct FingerprintVerifier {
    pins: Option<Vec<[u8; 32]>>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fingerprint: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        match &self.pins {
            Some(pins) if !pins.contains(&fingerprint) => Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )),
            _ => Ok(ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
enum ClientAuth {
    Secret {
        secret_file: PathBuf,
    },
    Certificate {
        cert_file: PathBuf,
        key_file: PathBuf,
    },
}

#[derive(Serialize)]
struct ClientAssertionClaims<'a> {
    aud: &'a str,
    iss: &'a str,
    sub: &'a str,
    jti: String,
    iat: u64,
    nbf: u64,
    exp: u64,
}

#[derive(Serialize)]
struct VerifyRequest<'a> {
    upn: &'a str,
    password: &'a str,
    otp: &'a str,
}

#[derive(Deserialize)]
struct TokenReply {
    access_token: String,
}

#[derive(Deserialize)]
struct VerifyReply {
    result: bool,
}

impl Config {
    fn load(path: &Path) -> Result<Self, String> {
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir))
        {
            return Err("config path must be absolute and cannot contain '..'".into());
        }
        let bytes = read_root_only(path, "config file")?;
        let raw = String::from_utf8(bytes).map_err(|_| "config file must be UTF-8")?;
        toml::from_str(&raw).map_err(|_| "invalid config file".into())
    }

    fn validate(&self) -> Result<(), String> {
        if self.endpoint.trim_end_matches('/').is_empty()
            || self.tenant.is_empty()
            || self.user_domain.is_empty()
            || self.client_id.is_empty()
            || self.api_scope.is_empty()
        {
            return Err(
                "endpoint, tenant, user_domain, client_id, and api_scope are required".into(),
            );
        }
        if !valid_path_segment(&self.tenant) || !valid_path_segment(&self.user_domain) {
            return Err(
                "tenant and user_domain must contain only letters, digits, dots, and hyphens"
                    .into(),
            );
        }
        let endpoint = reqwest::Url::parse(self.endpoint.trim_end_matches('/'))
            .map_err(|_| "endpoint must be an absolute URL")?;
        if !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err("endpoint cannot contain credentials, a query, or a fragment".into());
        }
        if endpoint.scheme() != "https"
            && !(endpoint.scheme() == "http"
                && matches!(endpoint.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")))
        {
            return Err("endpoint must use HTTPS (HTTP is allowed only for localhost)".into());
        }
        if self
            .local_users
            .iter()
            .any(|name| name.is_empty() || name.contains('@'))
        {
            return Err("local_users must contain short, non-empty Unix account names".into());
        }
        self.api_trust()?;
        Ok(())
    }

    fn api_trust(&self) -> Result<ApiTrust<'_>, String> {
        let pins = match &self.api_cert_pin_sha256 {
            CertPins::One(pin) => std::slice::from_ref(pin),
            CertPins::Many(pins) => pins.as_slice(),
        };
        if !pins.is_empty() {
            return pins
                .iter()
                .map(|pin| parse_fingerprint(pin))
                .collect::<Option<Vec<_>>>()
                .map(ApiTrust::Pinned)
                .ok_or_else(|| {
                    "api_cert_pin_sha256 must contain SHA-256 certificate fingerprints in hex"
                        .into()
                });
        }
        Ok(match &self.api_ca_file {
            Some(path) => ApiTrust::CaFile(path),
            None if self.api_tls_insecure_trust_all => ApiTrust::InsecureTrustAll,
            None => ApiTrust::PublicRoots,
        })
    }

    fn validate_files(&self) -> Result<(), String> {
        if let ApiTrust::CaFile(path) = self.api_trust()? {
            let pem = read_root_only(path, "API CA certificate file")?;
            parse_ca_bundle(&pem)?;
        }
        match &self.client_auth {
            ClientAuth::Secret { secret_file } => {
                if read_secret(secret_file)?.is_empty() {
                    return Err("client secret file is empty".into());
                }
            }
            ClientAuth::Certificate {
                cert_file,
                key_file,
            } => {
                let cert_pem = read_root_only(cert_file, "client certificate file")?;
                let (_, certificate) =
                    parse_x509_pem(&cert_pem).map_err(|_| "invalid client certificate PEM")?;
                if certificate.label != "CERTIFICATE" {
                    return Err(
                        "client certificate file must contain a CERTIFICATE PEM block".into(),
                    );
                }
                let key_pem = read_secret(key_file)?;
                EncodingKey::from_rsa_pem(&key_pem).map_err(|_| {
                    "client certificate key must be an RSA private key in PEM format"
                })?;
            }
        }
        Ok(())
    }

    // Accounts the Auth API must never decide: names in `local_users`, system
    // accounts below `min_uid` (root included), and names NSS does not know.
    // These are left to the next PAM module. Without any `local_users` there
    // is no break-glass account, so every account is treated as local.
    fn handled_locally(&self, username: &str) -> bool {
        if self.local_users.is_empty() {
            return true;
        }
        if self
            .local_users
            .iter()
            .any(|name| name.eq_ignore_ascii_case(username))
        {
            return true;
        }
        match lookup_ids(username) {
            Some((uid, _)) => uid < self.min_uid,
            None => true,
        }
    }

    // The Auth API is only used while a working break-glass account exists:
    // at least one `local_users` entry must be UID 0 or be granted ALL
    // commands by the local sudoers files (a best-effort reading of them).
    fn break_glass_problem(&self) -> Option<&'static str> {
        if self.local_users.is_empty() {
            return Some("local_users is not set");
        }
        let mut lines = Vec::new();
        collect_sudoers(Path::new(SUDOERS_PATH), 0, &mut lines);
        if self
            .local_users
            .iter()
            .filter_map(|name| load_account(name))
            .any(|account| account.uid == 0 || sudoers_grants_all(&lines, &account))
        {
            return None;
        }
        Some("no account in local_users has full sudo access in the local sudoers files")
    }

    fn token_endpoint(&self) -> String {
        format!(
            "{}/{}/oauth2/v2.0/token",
            self.endpoint.trim_end_matches('/'),
            self.tenant
        )
    }

    fn verify_endpoint(&self) -> String {
        format!(
            "{}/{}/api/v1/authenticate",
            self.endpoint.trim_end_matches('/'),
            self.tenant
        )
    }

    fn http_client(&self) -> Result<Client, String> {
        // Proxy environment variables are ignored: the host process may be a
        // setuid program whose environment belongs to the invoking user.
        let mut builder = Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy();
        let pins = match self.api_trust()? {
            ApiTrust::PublicRoots => return build_client(builder),
            ApiTrust::CaFile(path) => {
                // A configured CA replaces the built-in roots instead of adding to them.
                builder = builder.tls_built_in_root_certs(false);
                let pem = read_root_only(path, "API CA certificate file")?;
                for cert in parse_ca_bundle(&pem)? {
                    builder = builder.add_root_certificate(cert);
                }
                return build_client(builder);
            }
            ApiTrust::Pinned(pins) => Some(pins),
            ApiTrust::InsecureTrustAll => None,
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(FingerprintVerifier {
            pins,
            algorithms: provider.signature_verification_algorithms,
        });
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| "cannot initialize HTTPS client")?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        build_client(builder.use_preconfigured_tls(tls))
    }

    fn access_token(&self, client: &Client) -> Result<Zeroizing<String>, String> {
        let token_url = self.token_endpoint();
        let mut form = vec![
            ("grant_type", "client_credentials".to_owned()),
            ("client_id", self.client_id.clone()),
            ("scope", self.api_scope.clone()),
        ];
        match &self.client_auth {
            ClientAuth::Secret { secret_file } => {
                let secret = read_secret(secret_file)?;
                form.push((
                    "client_secret",
                    String::from_utf8_lossy(&secret).trim().to_owned(),
                ));
            }
            ClientAuth::Certificate {
                cert_file,
                key_file,
            } => {
                let cert_pem = read_root_only(cert_file, "client certificate file")?;
                let (_, pem) =
                    parse_x509_pem(&cert_pem).map_err(|_| "invalid client certificate PEM")?;
                let digest = Sha1::digest(&pem.contents);
                let key_pem = read_secret(key_file)?;
                let encoding_key = EncodingKey::from_rsa_pem(&key_pem).map_err(|_| {
                    "client certificate key must be an RSA private key in PEM format"
                })?;
                let now = unix_time()?;
                let claims = ClientAssertionClaims {
                    aud: &token_url,
                    iss: &self.client_id,
                    sub: &self.client_id,
                    jti: Uuid::new_v4().to_string(),
                    iat: now,
                    nbf: now,
                    exp: now + 300,
                };
                let mut header = Header::new(Algorithm::RS256);
                header.x5t = Some(URL_SAFE_NO_PAD.encode(digest));
                let assertion = encode(&header, &claims, &encoding_key)
                    .map_err(|_| "could not sign client assertion")?;
                form.push((
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
                ));
                form.push(("client_assertion", assertion));
            }
        }
        let sent = client.post(&token_url).form(&form).send();
        for (_, value) in form.iter_mut() {
            value.zeroize();
        }
        let response =
            sent.map_err(|error| format!("token endpoint request failed: {error:?}"))?;
        if !response.status().is_success() {
            return Err("token endpoint rejected the application credentials".into());
        }
        response
            .json::<TokenReply>()
            .map(|reply| Zeroizing::new(reply.access_token))
            .map_err(|_| "invalid token endpoint response".into())
    }

    fn verify(
        &self,
        client: &Client,
        upn: &str,
        password: &str,
        otp: &str,
    ) -> Result<bool, String> {
        let token = self.access_token(client)?;
        let response = client
            .post(self.verify_endpoint())
            .bearer_auth(token.as_str())
            .json(&VerifyRequest { upn, password, otp })
            .send()
            .map_err(|error| format!("credential verification request failed: {error:?}"))?;
        if !response.status().is_success() {
            return Err("credential verification service returned an error".into());
        }
        response
            .json::<VerifyReply>()
            .map(|reply| reply.result)
            .map_err(|_| "invalid credential verification response".into())
    }
}

fn parse_ca_bundle(pem: &[u8]) -> Result<Vec<reqwest::Certificate>, String> {
    let mut remaining = pem;
    let mut certificates = Vec::new();
    while remaining.iter().any(|byte| !byte.is_ascii_whitespace()) {
        let (rest, certificate) =
            parse_x509_pem(remaining).map_err(|_| "invalid API CA certificate bundle PEM")?;
        if certificate.label != "CERTIFICATE" {
            return Err("API CA bundle may contain only CERTIFICATE PEM blocks".into());
        }
        certificates.push(
            reqwest::Certificate::from_der(&certificate.contents)
                .map_err(|_| "invalid certificate in API CA bundle")?,
        );
        remaining = rest;
    }
    if certificates.is_empty() {
        return Err("API CA certificate bundle contains no certificates".into());
    }
    Ok(certificates)
}

fn build_client(builder: reqwest::blocking::ClientBuilder) -> Result<Client, String> {
    builder
        .build()
        .map_err(|_| "cannot initialize HTTPS client".into())
}

// Parse a SHA-256 fingerprint written as 64 hex digits, optionally separated
// by colons as `openssl x509 -fingerprint` prints them.
fn parse_fingerprint(text: &str) -> Option<[u8; 32]> {
    let digits: Vec<u8> = text.bytes().filter(|byte| *byte != b':').collect();
    if digits.len() != 64 || !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut fingerprint = [0u8; 32];
    for (byte, pair) in fingerprint.iter_mut().zip(digits.chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(fingerprint)
}

fn default_min_uid() -> libc::uid_t {
    DEFAULT_MIN_UID
}

fn valid_path_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
}

fn read_secret(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    read_root_only(path, "client secret or private key file").map(Zeroizing::new)
}

// Read and validate the same open file descriptor to avoid following a final
// symlink or checking one file and then reading a replacement. Files may be
// 0400 or 0600, but no group/other permission bits are accepted.
fn read_root_only(path: &Path, description: &str) -> Result<Vec<u8>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| format!("cannot open {description}"))?;
    let metadata = file
        .metadata()
        .map_err(|_| format!("cannot inspect {description}"))?;
    let permissions = metadata.mode() & 0o7777;
    if !metadata.is_file() || metadata.uid() != 0 || (permissions != 0o400 && permissions != 0o600)
    {
        return Err(format!(
            "{description} must be a regular file owned by root with mode 0400 or 0600"
        ));
    }
    let mut contents = Vec::new();
    (&mut file)
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut contents)
        .map_err(|_| format!("cannot read {description}"))?;
    if contents.len() as u64 > MAX_FILE_BYTES {
        contents.zeroize();
        return Err(format!("{description} is too large"));
    }
    Ok(contents)
}

struct Account {
    name: String,
    uid: libc::uid_t,
    gids: Vec<libc::gid_t>,
    groups: Vec<String>,
}

// Resolve an account's UID and primary GID through NSS. `None` means the host
// does not know the account or the lookup failed.
fn lookup_ids(name: &str) -> Option<(libc::uid_t, libc::gid_t)> {
    let c_name = CString::new(name).ok()?;
    let mut buffer: Vec<libc::c_char> = vec![0; 4096];
    loop {
        let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = ptr::null_mut();
        let rc = unsafe {
            libc::getpwnam_r(
                c_name.as_ptr(),
                &mut passwd,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buffer.len() < 1024 * 1024 {
            buffer.resize(buffer.len() * 4, 0);
            continue;
        }
        if rc != 0 || result.is_null() {
            return None;
        }
        return Some((passwd.pw_uid, passwd.pw_gid));
    }
}

fn group_name(gid: libc::gid_t) -> Option<String> {
    let mut buffer: Vec<libc::c_char> = vec![0; 4096];
    loop {
        let mut group: libc::group = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::group = ptr::null_mut();
        let rc = unsafe {
            libc::getgrgid_r(
                gid,
                &mut group,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buffer.len() < 1024 * 1024 {
            buffer.resize(buffer.len() * 4, 0);
            continue;
        }
        if rc != 0 || result.is_null() || group.gr_name.is_null() {
            return None;
        }
        return unsafe { CStr::from_ptr(group.gr_name) }
            .to_str()
            .ok()
            .map(str::to_owned);
    }
}

// Resolve an account together with all of its groups.
fn load_account(name: &str) -> Option<Account> {
    let (uid, gid) = lookup_ids(name)?;
    let c_name = CString::new(name).ok()?;
    let mut gids: Vec<libc::gid_t> = vec![0; 64];
    let mut count = gids.len() as libc::c_int;
    // The group types differ between platforms, hence the inferred casts.
    while unsafe {
        libc::getgrouplist(
            c_name.as_ptr(),
            gid as _,
            gids.as_mut_ptr() as *mut _,
            &mut count,
        )
    } < 0
    {
        if gids.len() >= 65536 {
            return None;
        }
        gids.resize(gids.len() * 4, 0);
        count = gids.len() as libc::c_int;
    }
    gids.truncate(count.max(0) as usize);
    let groups = gids.iter().filter_map(|gid| group_name(*gid)).collect();
    Some(Account {
        name: name.to_owned(),
        uid,
        gids,
        groups,
    })
}

// sudoers files are normally 0440 root:root and may be symlinks, so they get
// a looser check than the module's own files: root-owned and not writable by
// group or others.
fn read_sudoers_file(path: &Path) -> Option<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return None;
    }
    let mut contents = Vec::new();
    (&mut file)
        .take(MAX_FILE_BYTES)
        .read_to_end(&mut contents)
        .ok()?;
    String::from_utf8(contents).ok()
}

// Join continuation lines and drop comments and blank lines. A `#` starts a
// comment unless it introduces a numeric ID (`#1000`, `%#10`) or an include
// directive at the start of the line.
fn logical_lines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut pending = String::new();
    for raw in text.lines() {
        if let Some(continued) = raw.strip_suffix('\\') {
            pending.push_str(continued);
            continue;
        }
        pending.push_str(raw);
        let bytes = pending.as_bytes();
        let comment = (0..bytes.len()).find(|&index| {
            bytes[index] == b'#'
                && !bytes.get(index + 1).is_some_and(u8::is_ascii_digit)
                && !(index == 0 && pending.starts_with("#include"))
        });
        let line = pending[..comment.unwrap_or(pending.len())].trim();
        if !line.is_empty() {
            lines.push(line.to_owned());
        }
        pending.clear();
    }
    lines
}

// Collect the logical lines of a sudoers file and everything it includes.
fn collect_sudoers(path: &Path, depth: u8, lines: &mut Vec<String>) {
    let Some(text) = read_sudoers_file(path) else {
        return;
    };
    let resolve = |target: &str| {
        let target = Path::new(target.trim().trim_matches('"'));
        path.parent().unwrap_or(Path::new("/")).join(target)
    };
    for line in logical_lines(&text) {
        // `@includedir <path>` or `#include <path>`, separated by any whitespace.
        let directive = line
            .strip_prefix('@')
            .or_else(|| line.strip_prefix('#'))
            .and_then(|rest| rest.split_once(char::is_whitespace));
        if let Some(("includedir", target)) = directive {
            let Ok(entries) = std::fs::read_dir(resolve(target)) else {
                continue;
            };
            let mut names: Vec<_> = entries
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.path())
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| !name.contains('.') && !name.ends_with('~'))
                })
                .collect();
            names.sort();
            if depth < MAX_SUDOERS_DEPTH {
                for name in names {
                    collect_sudoers(&name, depth + 1, lines);
                }
            }
        } else if let Some(("include", target)) = directive {
            if depth < MAX_SUDOERS_DEPTH {
                collect_sudoers(&resolve(target), depth + 1, lines);
            }
        } else {
            lines.push(line);
        }
    }
}

fn sudoers_item_names(
    item: &str,
    account: &Account,
    aliases: &HashMap<&str, Vec<&str>>,
    depth: u8,
) -> bool {
    if item == "ALL" || item == account.name {
        return true;
    }
    if let Some(gid) = item.strip_prefix("%#") {
        return gid.parse().is_ok_and(|gid| account.gids.contains(&gid));
    }
    if let Some(group) = item.strip_prefix('%') {
        return account.groups.iter().any(|name| name == group);
    }
    if let Some(uid) = item.strip_prefix('#') {
        return uid.parse() == Ok(account.uid);
    }
    depth < MAX_SUDOERS_DEPTH
        && aliases.get(item).is_some_and(|members| {
            members
                .iter()
                .any(|member| sudoers_item_names(member, account, aliases, depth + 1))
        })
}

// True if the command list of a user specification contains `ALL` to be run
// as root, for example `(ALL:ALL) NOPASSWD: ALL`.
fn sudoers_commands_grant_all(commands: &str) -> bool {
    let mut rest = commands;
    let mut as_root = true;
    loop {
        rest = rest.trim_start();
        if let Some(runas) = rest.strip_prefix('(') {
            let Some((runas, after)) = runas.split_once(')') else {
                return false;
            };
            // Any exclusion in the run-as list is treated as excluding root.
            let users = runas.split(':').next().unwrap_or("");
            as_root = !users.contains('!')
                && users
                    .split(',')
                    .any(|user| matches!(user.trim(), "ALL" | "root" | "#0"));
            rest = after.trim_start();
        }
        while let Some((tag, after)) = rest.split_once(':') {
            if tag.is_empty() || !tag.bytes().all(|byte| byte.is_ascii_uppercase() || byte == b'_')
            {
                break;
            }
            rest = after.trim_start();
        }
        let (command, after) = rest.split_once(',').unwrap_or((rest, ""));
        if as_root && command.trim() == "ALL" {
            return true;
        }
        if after.is_empty() {
            return false;
        }
        rest = after;
    }
}

// Best-effort reading of sudoers rules: true if a user specification naming
// `account` grants ALL commands as root. Host lists are not evaluated, and
// netgroups and non-file sources (LDAP, sssd) are not consulted.
fn sudoers_grants_all(lines: &[String], account: &Account) -> bool {
    let mut aliases: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut rules = Vec::new();
    for line in lines {
        if let Some(definitions) = line.strip_prefix("User_Alias") {
            for definition in definitions.split(':') {
                if let Some((name, members)) = definition.split_once('=') {
                    aliases.insert(name.trim(), members.split(',').map(str::trim).collect());
                }
            }
        } else if !["Defaults", "Host_Alias", "Runas_Alias", "Cmnd_Alias", "Cmd_Alias"]
            .iter()
            .any(|keyword| line.starts_with(keyword))
        {
            rules.push(line.as_str());
        }
    }
    rules.iter().any(|rule| {
        let Some((subjects, commands)) = rule.split_once('=') else {
            return false;
        };
        // The user list ends at the first whitespace that does not follow a comma.
        let mut users = String::new();
        for word in subjects.split_whitespace() {
            if !users.is_empty() && !users.ends_with(',') && !word.starts_with(',') {
                break;
            }
            users.push_str(word);
        }
        let mut named = false;
        for item in users.split(',') {
            match item.strip_prefix('!') {
                Some(excluded) if sudoers_item_names(excluded, account, &aliases, 0) => {
                    return false
                }
                Some(_) => {}
                None => named |= sudoers_item_names(item, account, &aliases, 0),
            }
        }
        named && sudoers_commands_grant_all(commands)
    })
}

fn unix_time() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| "system clock is before Unix epoch".into())
}

fn log(message: &str) {
    if let Ok(c_message) = CString::new(format!("pam_rust_oidc: {message}")) {
        unsafe {
            libc::syslog(
                libc::LOG_AUTHPRIV | libc::LOG_NOTICE,
                b"%s\0".as_ptr() as *const _,
                c_message.as_ptr(),
            );
        }
    }
}

fn conversation(
    pamh: *mut libc::c_void,
    prompt: &str,
    style: libc::c_int,
) -> Result<Zeroizing<Vec<u8>>, libc::c_int> {
    let mut item: *const libc::c_void = ptr::null();
    let rc = unsafe { pam_get_item(pamh, PAM_CONV_ITEM, &mut item) };
    if rc != PAM_SUCCESS || item.is_null() {
        return Err(PAM_SERVICE_ERR);
    }
    let conv = unsafe { &*(item as *const PamConv) };
    let callback = conv.conv.ok_or(PAM_SERVICE_ERR)?;
    let prompt_c = CString::new(prompt).map_err(|_| PAM_SERVICE_ERR)?;
    let message = PamMessage {
        msg_style: style,
        msg: prompt_c.as_ptr(),
    };
    let message_ptr = &message as *const PamMessage;
    let mut response: *mut PamResponse = ptr::null_mut();
    let mut messages = message_ptr as *const PamMessage;
    let rc = unsafe { callback(1, &mut messages, &mut response, conv.appdata_ptr) };
    if response.is_null() {
        return Err(PAM_SERVICE_ERR);
    }
    if rc != PAM_SUCCESS {
        unsafe { release_pam_response(response) };
        return Err(PAM_SERVICE_ERR);
    }
    let raw = unsafe { (*response).resp };
    if raw.is_null() {
        unsafe { release_pam_response(response) };
        return Err(PAM_SERVICE_ERR);
    }
    let answer = Zeroizing::new(unsafe { CStr::from_ptr(raw) }.to_bytes().to_vec());
    unsafe { release_pam_response(response) };
    Ok(answer)
}

// Store the password as PAM_AUTHTOK so the next module (pam_unix with
// use_first_pass) can check it without prompting again. PAM copies the value.
unsafe fn set_authtok(pamh: *mut libc::c_void, password: &[u8]) -> Result<(), libc::c_int> {
    let mut token = Zeroizing::new(Vec::with_capacity(password.len() + 1));
    token.extend_from_slice(password);
    token.push(0);
    let rc = pam_set_item(pamh, PAM_AUTHTOK_ITEM, token.as_ptr() as *const libc::c_void);
    if rc != PAM_SUCCESS {
        return Err(PAM_SERVICE_ERR);
    }
    Ok(())
}

unsafe fn release_pam_response(response: *mut PamResponse) {
    if response.is_null() {
        return;
    }
    let raw = (*response).resp;
    if !raw.is_null() {
        let raw_len = libc::strlen(raw);
        std::slice::from_raw_parts_mut(raw as *mut u8, raw_len).zeroize();
        libc::free(raw as *mut libc::c_void);
    }
    libc::free(response as *mut libc::c_void);
}

unsafe fn pam_user(pamh: *mut libc::c_void) -> Result<String, libc::c_int> {
    let mut user: *const libc::c_char = ptr::null();
    let rc = pam_get_user(pamh, &mut user, ptr::null());
    if rc != PAM_SUCCESS || user.is_null() {
        return Err(PAM_AUTH_ERR);
    }
    CStr::from_ptr(user)
        .to_str()
        .map(str::to_owned)
        .map_err(|_| PAM_AUTH_ERR)
}

fn module_config(argc: libc::c_int, argv: *const *const libc::c_char) -> Result<PathBuf, String> {
    if argc <= 0 || argv.is_null() {
        return Err("config=/absolute/path is required".into());
    }
    let mut found = None;
    for index in 0..argc as isize {
        let arg_ptr = unsafe { *argv.offset(index) };
        if arg_ptr.is_null() {
            continue;
        }
        let arg = unsafe { CStr::from_ptr(arg_ptr) }
            .to_str()
            .map_err(|_| "invalid module argument")?;
        if let Some(path) = arg.strip_prefix("config=") {
            if found.is_some() || path.is_empty() {
                return Err("provide exactly one config path".into());
            }
            found = Some(PathBuf::from(path));
        } else {
            return Err("unknown module argument".into());
        }
    }
    found.ok_or_else(|| "config=/absolute/path is required".into())
}

unsafe fn authenticate(
    pamh: *mut libc::c_void,
    argc: libc::c_int,
    argv: *const *const libc::c_char,
) -> libc::c_int {
    let username = match pam_user(pamh) {
        Ok(value) => value,
        Err(_) => {
            log("PAM did not provide a username");
            return PAM_SERVICE_ERR;
        }
    };
    // A broken config or a missing break-glass account must not lock out
    // local accounts: the module then works as local authentication only.
    let setup = (|| -> Result<Config, String> {
        let path = module_config(argc, argv)?;
        let config = Config::load(&path)?;
        config.validate()?;
        config.validate_files()?;
        match config.break_glass_problem() {
            Some(problem) => Err(problem.into()),
            None => Ok(config),
        }
    })();
    // In local-only mode the prompt says so and no MFA code is asked for.
    // Otherwise every account sees the same conversation whether it is
    // local, remote, or unknown.
    let local_only = setup.is_err();
    let prompts = (|| -> Result<_, String> {
        let label = if local_only {
            "[local] Password:"
        } else {
            "[rust-oidc] Password:"
        };
        let password = conversation(pamh, label, PAM_PROMPT_ECHO_OFF)
            .map_err(|_| "password prompt failed")?;
        let otp = if local_only {
            Zeroizing::new(Vec::new())
        } else {
            conversation(pamh, "[rust-oidc] MFA Code:", PAM_PROMPT_ECHO_OFF)
                .map_err(|_| "OTP prompt failed")?
        };
        set_authtok(pamh, &password).map_err(|_| "could not store the password for PAM")?;
        Ok((password, otp))
    })();
    let (password, otp) = match prompts {
        Ok(value) => value,
        Err(message) => {
            log(&message);
            return PAM_SERVICE_ERR;
        }
    };
    let config = match setup {
        Ok(value) => value,
        Err(message) => {
            log(&format!("{message}; local authentication only"));
            return PAM_IGNORE;
        }
    };
    if matches!(config.api_trust(), Ok(ApiTrust::InsecureTrustAll)) {
        log("warning: api_tls_insecure_trust_all is set; the Auth API certificate is not verified");
    }
    if config.handled_locally(&username) {
        return PAM_IGNORE;
    }
    let result = (|| -> Result<bool, String> {
        if username.is_empty() || username.contains('@') || username.chars().any(char::is_control) {
            return Err("expected a short Unix username".into());
        }
        let (Ok(password), Ok(otp)) = (std::str::from_utf8(&password), std::str::from_utf8(&otp))
        else {
            return Ok(false);
        };
        let upn = format!("{}@{}", username, config.user_domain);
        let client = config.http_client()?;
        config.verify(&client, &upn, password, otp)
    })();
    match result {
        Ok(true) => PAM_SUCCESS,
        Ok(false) => PAM_AUTH_ERR,
        Err(message) => {
            log(&message);
            PAM_SERVICE_ERR
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut libc::c_void,
    _flags: libc::c_int,
    argc: libc::c_int,
    argv: *const *const libc::c_char,
) -> libc::c_int {
    // A panic must not unwind into the host process; fail closed instead.
    std::panic::catch_unwind(|| authenticate(pamh, argc, argv)).unwrap_or(PAM_SERVICE_ERR)
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut libc::c_void,
    _flags: libc::c_int,
    _argc: libc::c_int,
    _argv: *const *const libc::c_char,
) -> libc::c_int {
    PAM_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(extra: &str) -> Config {
        toml::from_str(&format!(
            r#"
            endpoint = "https://auth.example.net/rust-oidc"
            tenant = "example.net"
            user_domain = "example.net"
            client_id = "client"
            api_scope = "api://api-auth/.default"
            {extra}
            [client_auth]
            type = "secret"
            secret_file = "/etc/pam_rust_oidc/client-secret"
            "#
        ))
        .unwrap()
    }

    #[test]
    fn accepts_valid_config() {
        let config = config("");
        assert!(config.validate().is_ok());
        assert_eq!(config.min_uid, DEFAULT_MIN_UID);
    }

    #[test]
    fn rejects_plain_http_except_localhost() {
        let mut config = config("");
        config.endpoint = "http://auth.example.net".into();
        assert!(config.validate().is_err());
        for endpoint in ["http://localhost:8080", "http://127.0.0.1", "http://[::1]:8080"] {
            config.endpoint = endpoint.into();
            assert!(config.validate().is_ok(), "{endpoint}");
        }
    }

    #[test]
    fn rejects_endpoint_credentials_and_query() {
        let mut config = config("");
        for endpoint in ["https://u:p@auth.example.net", "https://auth.example.net/?a=b"] {
            config.endpoint = endpoint.into();
            assert!(config.validate().is_err(), "{endpoint}");
        }
    }

    #[test]
    fn rejects_dot_path_segments() {
        for value in ["", ".", "..", "a/b", "a b"] {
            assert!(!valid_path_segment(value), "{value:?}");
        }
        assert!(valid_path_segment("example.net"));
    }

    #[test]
    fn local_users_match_ignores_case() {
        let config = config(r#"local_users = ["james"]"#);
        assert!(config.handled_locally("james"));
        assert!(config.handled_locally("James"));
    }

    #[test]
    fn every_account_is_local_without_local_users() {
        for extra in ["", "local_users = []"] {
            let config = config(extra);
            assert!(config.validate().is_ok());
            assert_eq!(config.break_glass_problem(), Some("local_users is not set"));
            assert!(config.handled_locally("james"), "{extra:?}");
        }
    }

    #[test]
    fn break_glass_needs_a_sudo_capable_account() {
        let unknown = config(r#"local_users = ["no-such-account-pam-rust-oidc"]"#);
        assert!(unknown.break_glass_problem().is_some());
        let root = config(r#"local_users = ["root"]"#);
        assert_eq!(root.break_glass_problem(), None);
    }

    #[test]
    fn system_and_unknown_accounts_are_local() {
        let config = config(r#"local_users = ["james"]"#);
        assert!(config.handled_locally("root"));
        assert!(config.handled_locally("no-such-account-pam-rust-oidc"));
    }

    fn account() -> Account {
        Account {
            name: "admin".into(),
            uid: 1000,
            gids: vec![1000, 10],
            groups: vec!["admin".into(), "wheel".into()],
        }
    }

    fn grants(sudoers: &str) -> bool {
        sudoers_grants_all(&logical_lines(sudoers), &account())
    }

    #[test]
    fn sudoers_rules_that_grant_all() {
        for sudoers in [
            "admin ALL=(ALL) ALL",
            "admin ALL=(ALL:ALL) NOPASSWD: ALL",
            "%wheel\tALL=(ALL)\tALL",
            "%#10 ALL = ALL",
            "#1000 ALL=(root) ALL",
            "ALL ALL=(ALL) ALL",
            "root, admin ALL=(ALL) /bin/ls, ALL",
            "User_Alias OPS = bob, admin\nOPS ALL=(ALL) ALL",
            "# comment\nDefaults env_reset\nadmin ALL=(ALL) \\\n  NOPASSWD: ALL # trailing",
        ] {
            assert!(grants(sudoers), "{sudoers:?}");
        }
    }

    #[test]
    fn sudoers_rules_that_do_not_grant_all() {
        for sudoers in [
            "",
            "bob ALL=(ALL) ALL",
            "%sudo ALL=(ALL) ALL",
            "admin ALL=(ALL) /usr/bin/systemctl restart sshd",
            "admin ALL=(postgres) ALL",
            "admin ALL=(ALL, !root) ALL",
            "# admin ALL=(ALL) ALL",
            "#includedir /etc/sudoers.d",
            "%wheel, !admin ALL=(ALL) ALL",
            "Defaults:admin !requiretty",
            "User_Alias OPS = bob\nOPS ALL=(ALL) ALL",
        ] {
            assert!(!grants(sudoers), "{sudoers:?}");
        }
    }

    #[test]
    fn sudoers_includes_accept_any_whitespace() {
        let dir = std::env::temp_dir().join(format!("pam-rust-oidc-test-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("sudoers.d")).unwrap();
        std::fs::write(dir.join("sudoers.d/admins"), "admin ALL=(ALL) ALL\n").unwrap();
        std::fs::write(dir.join("extra"), "bob ALL=(ALL) ALL\n").unwrap();
        let main = dir.join("sudoers");
        std::fs::write(&main, "#includedir\tsudoers.d\n@include  extra\n").unwrap();
        let mut lines = Vec::new();
        collect_sudoers(&main, 0, &mut lines);
        std::fs::remove_dir_all(&dir).unwrap();
        // Files are only read when owned by root, so this passes vacuously otherwise.
        if unsafe { libc::geteuid() } == 0 {
            assert_eq!(lines, ["admin ALL=(ALL) ALL", "bob ALL=(ALL) ALL"]);
        } else {
            assert!(lines.is_empty());
        }
    }

    const PIN: &str = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:\
                       AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";

    #[test]
    fn parses_fingerprints() {
        let plain = PIN.replace(':', "").to_lowercase();
        assert_eq!(parse_fingerprint(PIN), parse_fingerprint(&plain));
        assert_eq!(parse_fingerprint(PIN).unwrap()[..3], [0xab, 0xcd, 0xef]);
        for bad in ["", "abcd", &plain[1..], &format!("{}zz", &plain[2..]), &format!("+{}", &plain[1..])] {
            assert!(parse_fingerprint(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn api_trust_precedence_is_pin_then_ca_then_trust_all() {
        let all = format!(
            "api_cert_pin_sha256 = \"{PIN}\"\napi_ca_file = \"/ca.pem\"\napi_tls_insecure_trust_all = true"
        );
        assert!(matches!(config(&all).api_trust(), Ok(ApiTrust::Pinned(pins)) if pins.len() == 1));
        let list = format!("api_cert_pin_sha256 = [\"{PIN}\", \"{PIN}\"]");
        assert!(matches!(config(&list).api_trust(), Ok(ApiTrust::Pinned(pins)) if pins.len() == 2));
        let ca = "api_ca_file = \"/ca.pem\"\napi_tls_insecure_trust_all = true";
        assert!(matches!(config(ca).api_trust(), Ok(ApiTrust::CaFile(_))));
        let insecure = "api_tls_insecure_trust_all = true";
        assert!(matches!(config(insecure).api_trust(), Ok(ApiTrust::InsecureTrustAll)));
        assert!(matches!(config("").api_trust(), Ok(ApiTrust::PublicRoots)));
        assert!(matches!(config("api_cert_pin_sha256 = []").api_trust(), Ok(ApiTrust::PublicRoots)));
    }

    #[test]
    fn rejects_malformed_pins() {
        let config = config(r#"api_cert_pin_sha256 = "not-a-fingerprint""#);
        assert!(config.validate().is_err());
    }

    #[test]
    fn fingerprint_verifier_checks_the_pin() {
        let certificate = CertificateDer::from(b"certificate".to_vec());
        let name = ServerName::try_from("auth.example.net").unwrap();
        let verify = |pins| {
            FingerprintVerifier {
                pins,
                algorithms: rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms,
            }
            .verify_server_cert(&certificate, &[], &name, &[], UnixTime::now())
            .is_ok()
        };
        let fingerprint: [u8; 32] = Sha256::digest(b"certificate").into();
        assert!(verify(Some(vec![[0; 32], fingerprint])));
        assert!(!verify(Some(vec![[0; 32]])));
        assert!(verify(None));
    }

    // Live handshake check. Run with, for example:
    //   PAM_OIDC_TEST_URL=https://auth.example.net PAM_OIDC_TEST_PIN=<hex> \
    //   cargo test -- --ignored live_tls
    #[test]
    #[ignore = "needs network; set PAM_OIDC_TEST_URL and PAM_OIDC_TEST_PIN"]
    fn live_tls_trust_modes() {
        let url = std::env::var("PAM_OIDC_TEST_URL").unwrap();
        let pin = std::env::var("PAM_OIDC_TEST_PIN").unwrap();
        let reaches = |extra: &str| {
            let client = config(extra).http_client().unwrap();
            client.get(&url).send().is_ok()
        };
        assert!(reaches(&format!("api_cert_pin_sha256 = \"{pin}\"")), "right pin");
        let wrong = "00".repeat(32);
        assert!(!reaches(&format!("api_cert_pin_sha256 = \"{wrong}\"")), "wrong pin");
        assert!(reaches("api_tls_insecure_trust_all = true"), "trust all");
        // The pin wins over trust-all.
        assert!(
            !reaches(&format!("api_cert_pin_sha256 = \"{wrong}\"\napi_tls_insecure_trust_all = true")),
            "wrong pin with trust all"
        );
    }

    #[test]
    fn rejects_unknown_config_fields() {
        assert!(toml::from_str::<Config>("bogus = 1").is_err());
    }
}

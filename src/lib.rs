use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::ffi::{CStr, CString};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::ptr;
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
    api_ca_file: Option<PathBuf>,
    client_auth: ClientAuth,
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
        Ok(())
    }

    fn validate_files(&self) -> Result<(), String> {
        if let Some(path) = &self.api_ca_file {
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
    // These are left to the next PAM module.
    fn handled_locally(&self, username: &str) -> bool {
        if self
            .local_users
            .iter()
            .any(|name| name.eq_ignore_ascii_case(username))
        {
            return true;
        }
        match lookup_uid(username) {
            Some(uid) => uid < self.min_uid,
            None => true,
        }
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
        if let Some(path) = &self.api_ca_file {
            // A configured CA replaces the built-in roots instead of adding to them.
            builder = builder.tls_built_in_root_certs(false);
            let pem = read_root_only(path, "API CA certificate file")?;
            for cert in parse_ca_bundle(&pem)? {
                builder = builder.add_root_certificate(cert);
            }
        }
        builder
            .build()
            .map_err(|_| "cannot initialize HTTPS client".into())
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

// Resolve an account's UID through NSS. `None` means the host does not know
// the account or the lookup failed.
fn lookup_uid(name: &str) -> Option<libc::uid_t> {
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
        return Some(passwd.pw_uid);
    }
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
    // Prompt before looking at the config or the account, so every account
    // sees the same conversation whether it is local, remote, or unknown.
    let prompts = (|| -> Result<_, String> {
        let password = conversation(pamh, "[rust-oidc] Password:", PAM_PROMPT_ECHO_OFF)
            .map_err(|_| "password prompt failed")?;
        let otp = conversation(pamh, "[rust-oidc] MFA Code:", PAM_PROMPT_ECHO_OFF)
            .map_err(|_| "OTP prompt failed")?;
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
    // A broken config must not lock out local accounts: defer to the next
    // module, which checks the stored password against the local database.
    let setup = (|| -> Result<Config, String> {
        let path = module_config(argc, argv)?;
        let config = Config::load(&path)?;
        config.validate()?;
        config.validate_files()?;
        Ok(config)
    })();
    let config = match setup {
        Ok(value) => value,
        Err(message) => {
            log(&format!("{message}; deferring to the next PAM module"));
            return PAM_IGNORE;
        }
    };
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
    fn system_and_unknown_accounts_are_local() {
        let config = config("");
        assert!(config.handled_locally("root"));
        assert!(config.handled_locally("no-such-account-pam-rust-oidc"));
    }

    #[test]
    fn rejects_unknown_config_fields() {
        assert!(toml::from_str::<Config>("bogus = 1").is_err());
    }
}

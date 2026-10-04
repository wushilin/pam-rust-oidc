# pam-rust-oidc

A Linux PAM authentication module that verifies a user's password and TOTP through
the `Credentials.Verify` Auth API. SSH supplies the short Unix username; the
module appends the configured `user_domain` to form the user's UPN.

The host must already resolve SSH users through NSS. This module authenticates
accounts; it does not create Unix identities.

The Auth API is never asked about these accounts. They are handed to the next
PAM authentication module with `PAM_IGNORE`, normally `pam_unix`:

- names listed in `local_users` (matched case-insensitively);
- system accounts with a UID below `min_uid` (default `1000`), which includes
  `root`;
- names NSS does not know.

`local_users` must name at least one account, so a break-glass account always
exists. If it is missing or empty, the module logs that and treats every
account as local: nothing is sent to the Auth API until it is set.

A break-glass account must also be able to administer the host. At least one
`local_users` entry has to be UID 0 or be granted `ALL` commands as root by
`/etc/sudoers` (and the files it includes). If none is, the module logs that
and treats every account as local, exactly as when `local_users` is unset.

The sudoers check is a best-effort reading of the local files: it does not see
rules from LDAP or sssd, does not evaluate host lists or netgroups, and does
not count rules limited to specific commands. If your break-glass account gets
sudo only through one of those, add a plain rule for it in `/etc/sudoers.d`.

The UID is whatever the host resolves for the name through NSS, whether the
account lives in `/etc/passwd` or comes from sssd/LDAP. An Auth API user named
`root@<user_domain>` therefore can never authenticate as the host's `root`.

The reverse is not automatic: every account with a UID of `min_uid` or above
is sent to the Auth API unless its name is in `local_users`. In particular:

- list local administrator accounts in that range (for example a UID 1000
  `admin` with sudo rights) in `local_users`; the UID rule cannot know who is
  in `wheel` or `sudoers`;
- `nobody` (UID 65534) is above `min_uid` and is treated as an Auth API
  account. Its shell is normally `nologin`, so a login goes nowhere, but add
  it to `local_users` to keep the request from being made;
- an Auth API account that has sudo rights makes the Auth API a root-level
  trust anchor for the host.

## Configuration

Create `/etc/pam_rust_oidc.toml`, owned by root with mode `0400` or `0600`.
The module refuses to run if the config, client secret/private key, client
certificate, or optional CA file is not a regular root-owned file with exactly
those owner-only permissions. Symlinks are rejected:

```toml
endpoint = "https://auth.example.net/rust-oidc"
tenant = "wushilin.net"
user_domain = "wushilin.net"
client_id = "your-client-application-id"
api_scope = "api://api-auth/.default"
local_users = ["james", "asdf"]

# Optional. Accounts with a UID below this are always treated as local.
min_uid = 1000

# Optional CA PEM/bundle for a private PKI or self-signed API server cert.
# When set, only these roots are trusted (the built-in public roots are
# dropped). Hostname and TLS verification stay on.
api_ca_file = "/etc/pam_rust_oidc/api-ca.pem"

[client_auth]
type = "secret"
secret_file = "/etc/pam_rust_oidc/client-secret"
```

For certificate client authentication, use instead:

```toml
[client_auth]
type = "certificate"
cert_file = "/etc/pam_rust_oidc/client-cert.pem"
key_file = "/etc/pam_rust_oidc/client-key.pem"
```

The certificate flow signs an RS256 client assertion. The private key file must
be PEM encoded and RSA. Keep the public client certificate uploaded to the
OIDC server; never upload the private key.

Set `api_scope` to the exact scope accepted by the Auth API. For example, this
may be `api://api-auth/.default` or `<uuid>/.default`. The module passes this
value unchanged to the token endpoint. Grant the client application
`Credentials.Verify` and assign the users who may authenticate to that
application in the server's admin console.

## PAM configuration

Install the shared library as `pam_rust_oidc.so` alongside the system's other
PAM modules. For an SSH service where local accounts should use `pam_unix` and
all other accounts should use the Auth API, the authentication stack can be
structured as follows (module paths and surrounding account/session rules vary
by distribution):

```text
auth [success=done ignore=ignore default=die] pam_rust_oidc.so config=/etc/pam_rust_oidc.toml
auth [success=done default=die] pam_unix.so use_first_pass
```

The module prompts every account for `[rust-oidc] Password:` and
`[rust-oidc] MFA Code:` before it looks at the config or the account, so local
and remote accounts see the same conversation. It stores the password as
`PAM_AUTHTOK`. For local accounts it discards the MFA code (they can press
Enter), contacts nothing, and returns `PAM_IGNORE`; `pam_unix` then checks the
stored password. Use `use_first_pass` so `pam_unix` never shows its own prompt.

For other names, API success ends the auth stack and an API rejection or
runtime error fails closed. For example, PAM user `james` is verified as
`james@wushilin.net`. Do not mark the OIDC module `sufficient` ahead of
`pam_unix`: that would let local users bypass their local password check.

If the config or one of its files is missing or invalid, the module logs the
problem and returns `PAM_IGNORE` for every account, so local and break-glass
accounts keep working. This is only safe while accounts meant for the Auth API
have no usable local password (a locked or absent shadow entry); do not use
`nullok` on `pam_unix` in this stack.

With sshd, enable `KbdInteractiveAuthentication`. Plain
`PasswordAuthentication` answers both prompts with the password, so Auth API
logins always fail there.

## Throttling

The Auth API sees every attempt as coming from this host, not from the remote
client, so its own rate limits cannot tell an attacker from a legitimate user.
Limit attempts on the host as well:

- per source address: sshd `PerSourcePenalties` (OpenSSH 9.8+) or fail2ban;
- per account: `pam_faillock` ahead of this module, with a threshold below the
  Auth API's failure block;
- use a separate client credential per host so one host can be revoked or
  throttled without affecting the others.

Public-key authentication is controlled by sshd. In common OpenSSH setups the
PAM `auth` stack is not used for successful public-key authentication, though
PAM account and session stacks can still run. Keep those stacks configured for
your host's account policy. This module has no account-phase check: a user
disabled in the Auth API can still log in with an existing SSH key.

## Install from a release

Each release publishes one prebuilt `x86_64` module per supported distribution
(Rocky Linux 8, Ubuntu 22.04 and 24.04, Debian 12 and 13) together with a
`SHA256SUMS` file. Download the asset for your distribution and `SHA256SUMS`
from the release page, then verify and install:

```sh
sha256sum --check --ignore-missing SHA256SUMS
install -o root -g root -m 0644 pam-rust-oidc-<distro>-x86_64.so \
  /usr/lib64/security/pam_rust_oidc.so
```

Use the distribution's PAM module directory as the destination (see below).

## Build

Build on a Linux system with PAM development headers/library installed:

```sh
cargo build --release
```

The shared library is `target/release/libpam_rust_oidc.so`. Install it in the
distribution's PAM module directory (often `/usr/lib/security`,
`/usr/lib/x86_64-linux-gnu/security`, or `/usr/lib64/security`).

The module logs only generic configuration/network failure descriptions to the
auth log. It never logs users' passwords, OTPs, application secrets, client
assertions, or access tokens. Requests have a 15-second timeout and fail closed.
Proxy environment variables are ignored. Secrets are wiped from the module's
own buffers on a best-effort basis; copies inside the HTTP and TLS libraries
are not.

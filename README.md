# pam-rust-oidc

A Linux PAM authentication module that verifies a user's password and TOTP through
the `Credentials.Verify` Auth API. SSH supplies the short Unix username; the
module appends the configured `user_domain` to form the user's UPN.

A login only works for a name that has a Unix account on the host. Create the
accounts yourself, or let the module create them at first login (see
[On-demand accounts](#on-demand-accounts)).

[Typical configuration](#typical-configuration) is a complete example to copy
from. [Setting up a host](#setting-up-a-host) explains every step, including
the sshd, sudo, SELinux and AppArmor configuration.

The Auth API is never asked about these accounts. They are handed to the next
PAM authentication module with `PAM_IGNORE`, normally `pam_unix`:

- names listed in `local_users` (matched case-insensitively);
- system accounts with a UID below `min_uid` (default `1000`), which includes
  `root`;
- names NSS does not know.

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

## Break-glass requirement

The Auth API is only used while a working break-glass account exists:

- `local_users` must name at least one account;
- at least one `local_users` entry must be UID 0 or be granted `ALL` commands
  as root by `/etc/sudoers` (and the files it includes).

If either condition fails, or the config or one of its files is missing or
invalid, the module logs the reason and works as local authentication only:
it prompts `[local] Password:`, asks for no MFA code, sends nothing to the
Auth API, and leaves every account to the next PAM module.

The sudoers check is a best-effort reading of the local files: it does not see
rules from LDAP or sssd, does not evaluate host lists or netgroups, and does
not count rules limited to specific commands. If your break-glass account gets
sudo only through one of those, add a plain rule for it in `/etc/sudoers.d`.

## Configuration

Create the config file, for example `/etc/pam_rust_oidc/config.toml`, owned by
root with mode `0400` or `0600`.
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

# Optional. How the API server certificate is trusted; see "API server trust".
# api_cert_pin_sha256 = "0E:5E:12:...:ED:FC"
# api_ca_file = "/etc/pam_rust_oidc/api-ca.pem"
# api_tls_insecure_trust_all = true

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

## On-demand accounts

Off by default. When enabled, the module creates Unix accounts for Auth API
users the first time they try to log in, and manages their sudo rule from
their roles:

```toml
[provisioning]
enabled = true
admin_role = "admin"              # role that grants sudo
pending_ttl_minutes = 2           # unused new accounts are deleted after this long
max_pending = 20                  # most new accounts waiting for a first login
working_dir = "/var/lib/pam_rust_oidc"

# Per source address: this many new accounts within the window stops account
# creation from that address for the ban time. 0 turns the limit off.
max_creations_per_address = 10
creation_window_minutes = 60
creation_ban_minutes = 60
tracked_addresses = 4096          # least recently seen addresses are forgotten
```

All of these are optional; the values shown are the defaults (except
`enabled`, which defaults to `false`).

sshd does not pass on what an unknown user types, so a new account cannot be
created and verified in one login. It takes two:

1. First attempt with a name the host does not know: the module creates a
   *pending* account (no home directory, no sudo, and a password hash made of
   random characters, so no password exists that matches it). The user sees the usual password and MFA prompts, the attempt
   fails and the connection is closed. Nothing tells the client that an
   account was created, so tell new users to expect one failed login.
2. Second attempt: the password and MFA code are verified by the Auth API as
   usual. On success the account becomes *active* and gets its home directory.

At every verified login of an account it created, the module compares the
roles the Auth API returns for this application with `admin_role`: with the role it writes
`/etc/sudoers.d/<username>` (`ALL=(ALL:ALL) ALL`), without it it removes that
file. It only ever touches files that carry its own header line; a rule an
administrator wrote by hand is left alone. Accounts the module did not create
(ones that existed before, or that an administrator added) are not managed at
all: they keep whatever sudo rights they were given on the host.

The sudo rule requires a password, and these accounts have no local password
anyone knows. For sudo to work for them, the module must also be in sudo's PAM
stack: see [step 5 of the setup](#5-sudo-pam-stack-etcpamdsudo).

Pending accounts that never complete a login are deleted after
`pending_ttl_minutes`. The check runs on each login attempt, so on a quiet
host they can stay longer. The account that is logging in at that moment is
never deleted, so a slow second login still works; if another attempt removed
it in the meantime, the next login is a first attempt again.

### Limits on account creation

Account creation can be triggered by anyone who can reach sshd, so it is
limited in two ways:

- `max_pending` caps how many accounts may be waiting for their first login,
  whatever the source.
- Each source address may create `max_creations_per_address` accounts within
  `creation_window_minutes`. The account that reaches the limit starts a ban
  of `creation_ban_minutes`, during which that address creates no accounts.
  The count starts again after the window or the ban.

A ban only stops new accounts. Existing accounts, including the break-glass
one, still log in from a banned address, and the client sees the usual prompts
either way. Loopback addresses (`127.0.0.0/8`, `::1`) are never counted, so
tests run on the host itself are not limited. Clients that share an address
(NAT, a jump host, a tunnel) share one count; raise the limit or set it to `0`
on hosts reached that way.

### Working directory

Everything the module keeps between logins is under `working_dir`, readable
by root only:

| Path | Content |
|---|---|
| `accounts/<name>` | one file per account the module created: `pending <time>` or `active <time>` |
| `stats/addresses` | accounts created per source address, and bans |
| `lock` | held while accounts or any of these files change, because every login runs in its own process |

The module creates the directory itself (mode `0700`, files `0600`). If it
already exists it must be a real directory, owned by root, with no access for
group or others; otherwise the module logs that and creates no accounts.

An account without a file in `accounts/` is never deleted by the module.
Removing `stats/addresses` clears all counts and bans.

### Things to know

- Accounts are created for names of lowercase letters, digits, `_` and `-`
  only (no dots: sudo ignores sudoers files with a dot in the name).
- A pending account is created for any such name, before anything is known
  about the user, so name-guessing traffic creates pending accounts within
  the limits above. They cannot be logged in to and are cleaned up, but while
  `max_pending` is reached no new account can be created.
- Roles are only seen at a password login. A public-key login does not update
  the sudo rule, and a role removed in the Auth API takes effect on this host
  at the user's next password login.
- Removing the admin role removes the module's sudo rule. It cannot undo what
  the user did while they had root, such as adding another rule, an SSH key or
  a second account.
- An active account whose user is later unassigned can no longer log in with
  a password, but the account is not deleted.
- With `api_tls_insecure_trust_all`, whoever can impersonate the API server
  can grant themselves the admin role. Pin the certificate before enabling
  this.
- On hosts with SELinux enforcing, the policy module and labels from
  [step 6 of the setup](#6-selinux-and-apparmor) are required.

## API server trust

By default the API server certificate must chain to a public CA and match the
endpoint's hostname. Three optional settings change that. Only the first one
present is used; the others are ignored:

1. `api_cert_pin_sha256`: the SHA-256 fingerprint of the server's certificate,
   or a list of fingerprints so the next certificate can be added before the
   server rotates to it. Only a server presenting one of these exact
   certificates (and holding its private key) is accepted. The CA chain,
   hostname and expiry date are not checked, so this works with self-signed
   certificates. When the server's certificate changes, Auth API logins fail
   until the pin is updated.
2. `api_ca_file`: a CA PEM/bundle for a private PKI. Only these roots are
   trusted (the built-in public roots are dropped). Hostname and expiry
   checks stay on.
3. `api_tls_insecure_trust_all = true`: accept any certificate. Anyone who can
   intercept the connection can then approve logins and read the passwords,
   MFA codes and client credentials sent to the API. Use it only on an
   isolated test network; the module logs a warning on every login while it
   is in effect.

Print a server's fingerprint with:

```sh
openssl s_client -connect auth.example.net:443 -servername auth.example.net </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256
```

The fingerprint may be written with or without colons, in either case.

## Typical configuration

A complete example for one host: certificate client authentication, a pinned
API certificate, a break-glass account named `breakglass`, on-demand accounts,
and sudo through the Auth API. Each step is explained under
[Setting up a host](#setting-up-a-host). Run everything as root and keep that
shell open until the last step has passed.

`/etc/pam_rust_oidc/config.toml`:

```toml
endpoint = "https://auth.example.net/rust-oidc"
tenant = "example.net"
user_domain = "example.net"
client_id = "your-client-application-id"
api_scope = "api://auth-api/.default"

# Checked against the local password, never sent to the Auth API.
local_users = ["breakglass"]

# Accept only this server certificate.
api_cert_pin_sha256 = "0E:5E:12:...:ED:FC"

[client_auth]
type = "certificate"
cert_file = "/etc/pam_rust_oidc/client-cert.pem"
key_file = "/etc/pam_rust_oidc/client-key.pem"

# Create accounts at first login; the "admin" role gets sudo.
[provisioning]
enabled = true
```

RHEL, Rocky, Oracle Linux:

```sh
# 1. Module, config and credentials (config.toml, client-cert.pem, client-key.pem)
install -o root -g root -m 0755 pam-rust-oidc-rocky8-x86_64.so /usr/lib64/security/pam_rust_oidc.so
install -d -o root -g root -m 0700 /etc/pam_rust_oidc
install -o root -g root -m 0600 config.toml client-cert.pem client-key.pem /etc/pam_rust_oidc/

# 2. Break-glass account
useradd -m -s /bin/bash breakglass && passwd breakglass
echo 'breakglass ALL=(ALL:ALL) ALL' > /etc/sudoers.d/breakglass && chmod 0440 /etc/sudoers.d/breakglass

# 3. sshd and sudo PAM stacks: the module goes in front of the existing auth lines
LINE='auth       [success=done ignore=ignore default=die] pam_rust_oidc.so config=/etc/pam_rust_oidc/config.toml'
cp -p /etc/pam.d/sshd /etc/pam.d/sudo /root/
sed -i "0,/^auth[[:space:]]/s||$LINE\n&|" /etc/pam.d/sshd
sed -i "0,/^auth[[:space:]]/s||$LINE\n&|" /etc/pam.d/sudo

# 4. sshd: keyboard-interactive for the two prompts
printf 'KbdInteractiveAuthentication yes\nUsePAM yes\n' > /etc/ssh/sshd_config.d/00-pam-rust-oidc.conf
sshd -t && systemctl reload sshd

# 5. SELinux, only if "getenforce" prints Enforcing (explained in step 6 of the setup)
semodule -i selinux/pam_rust_oidc.cil
semanage fcontext -a -t var_auth_t '/var/lib/pam_rust_oidc(/.*)?'
install -d -o root -g root -m 0700 /var/lib/pam_rust_oidc
restorecon -R /usr/lib64/security/pam_rust_oidc.so /etc/pam_rust_oidc /var/lib/pam_rust_oidc \
  /etc/pam.d/sshd /etc/pam.d/sudo /etc/ssh/sshd_config.d /etc/sudoers.d
```

Debian, Ubuntu:

```sh
# 1. Module, config and credentials
install -o root -g root -m 0755 pam-rust-oidc-ubuntu24.04-x86_64.so /usr/lib/x86_64-linux-gnu/security/pam_rust_oidc.so
install -d -o root -g root -m 0700 /etc/pam_rust_oidc
install -o root -g root -m 0600 config.toml client-cert.pem client-key.pem /etc/pam_rust_oidc/

# 2. Break-glass account
useradd -m -s /bin/bash breakglass && passwd breakglass
echo 'breakglass ALL=(ALL:ALL) ALL' > /etc/sudoers.d/breakglass && chmod 0440 /etc/sudoers.d/breakglass

# 3. sshd and sudo PAM stacks: the module goes in front of "@include common-auth"
LINE='auth       [success=done ignore=ignore default=die] pam_rust_oidc.so config=/etc/pam_rust_oidc/config.toml'
cp -p /etc/pam.d/sshd /etc/pam.d/sudo /root/
sed -i "0,/^@include common-auth/s||$LINE\n&|" /etc/pam.d/sshd
sed -i "0,/^@include common-auth/s||$LINE\n&|" /etc/pam.d/sudo

# 4. sshd: keyboard-interactive for the two prompts
printf 'KbdInteractiveAuthentication yes\nUsePAM yes\n' > /etc/ssh/sshd_config.d/00-pam-rust-oidc.conf
sshd -t && systemctl reload ssh

# 5. AppArmor: nothing to do unless sshd is confined (explained in step 6 of the setup)
aa-status 2>/dev/null | grep -i sshd || echo "sshd is not confined"
```

Then, from new connections and without closing the root shell:

```sh
ssh you@host                                 # your public-key login still works
ssh -o PubkeyAuthentication=no breakglass@host   # local password, Enter at the MFA prompt
ssh -o PubkeyAuthentication=no alice@host    # Auth API user: fails once (account created), then works
```

If something is wrong, restore the two PAM files from `/root`, remove
`/etc/ssh/sshd_config.d/00-pam-rust-oidc.conf` and reload sshd.

## Setting up a host

Seven steps. Keep a root shell open until the checks in step 7 pass, so a
mistake cannot lock you out.

### 1. Install the module

Copy the shared library into the distribution's PAM module directory as
`pam_rust_oidc.so`, owned by root, mode `0755`:

| Distribution family | Directory |
|---|---|
| RHEL, Rocky, Oracle, Alibaba Cloud Linux | `/usr/lib64/security` |
| Debian, Ubuntu (x86_64) | `/usr/lib/x86_64-linux-gnu/security` |
| Debian, Ubuntu (ARM64) | `/usr/lib/aarch64-linux-gnu/security` |

See [Install from a release](#install-from-a-release) or [Build](#build).

### 2. Write the config and create the break-glass account

Write the config file as described under [Configuration](#configuration). The
examples below assume `/etc/pam_rust_oidc/config.toml`.

Create a local account for emergencies, give it a strong password and full
sudo, and list it in `local_users`. Without it the module stays in local-only
mode (see [Break-glass requirement](#break-glass-requirement)):

```sh
useradd -m -s /bin/bash breakglass
passwd breakglass
echo 'breakglass ALL=(ALL:ALL) ALL' > /etc/sudoers.d/breakglass
chmod 0440 /etc/sudoers.d/breakglass
```

### 3. sshd PAM stack (`/etc/pam.d/sshd`)

Add one line in front of the existing authentication lines. Leave everything
else in the file as it is.

RHEL family: put it before `auth substack password-auth`:

```text
#%PAM-1.0
auth       [success=done ignore=ignore default=die] pam_rust_oidc.so config=/etc/pam_rust_oidc/config.toml
auth       substack     password-auth
auth       include      postlogin
...
```

Debian and Ubuntu: put it before `@include common-auth`:

```text
auth       [success=done ignore=ignore default=die] pam_rust_oidc.so config=/etc/pam_rust_oidc/config.toml
@include common-auth
...
```

What the control values mean:

- `success=done`: the Auth API accepted the login; nothing else is asked.
- `ignore=ignore`: a local account, or local-only mode; the distribution's
  own stack (`pam_unix`) checks the local password.
- `default=die`: the Auth API refused the login or could not be reached; the
  login fails. Do not use `sufficient` here: that would let a refused Auth API
  user fall through to a local password check.

The module prompts every account for `[rust-oidc] Password:` and
`[rust-oidc] MFA Code:` before it looks at the account, so local and remote
accounts see the same conversation. It stores the password for the modules
after it (`PAM_AUTHTOK`); `pam_unix` reuses it and does not prompt again.
Local accounts press Enter at the MFA prompt.

In local-only mode every account is left to `pam_unix`. That is only safe
while accounts meant for the Auth API have no usable local password, so do not
give them one, and avoid `nullok` on `pam_unix` where you can.

### 4. sshd settings

The two prompts need keyboard-interactive authentication. With plain password
authentication sshd answers both prompts with the password, so an Auth API
login always fails that way.

OpenSSH 8.2 and later (the main `sshd_config` includes
`/etc/ssh/sshd_config.d/*.conf`): create
`/etc/ssh/sshd_config.d/00-pam-rust-oidc.conf`. The name must sort first,
because sshd uses the first value it reads for each setting:

```text
# Auth API logins need two prompts, which only keyboard-interactive provides.
KbdInteractiveAuthentication yes
UsePAM yes

# Optional: allow the break-glass account plain password logins as well.
Match User breakglass
    PasswordAuthentication yes
```

Older OpenSSH (for example 8.0 on the RHEL 8 family) has no drop-in directory
and uses a different keyword that cannot be set per user. Edit
`/etc/ssh/sshd_config` instead:

```text
ChallengeResponseAuthentication yes
UsePAM yes
```

Keep `PermitRootLogin prohibit-password` (or `no`): with keyboard-interactive
on, `PermitRootLogin yes` lets root log in with its local password.

Check and apply. A reload does not drop existing sessions:

```sh
sshd -t && systemctl reload sshd     # the service is named "ssh" on Debian and Ubuntu
sshd -T -C user=someuser,host=x,addr=203.0.113.1 | grep -i -E 'kbdinteractive|passwordauth'
```

Public-key logins are unchanged: sshd does not run the PAM `auth` stack for
them.

### 5. sudo PAM stack (`/etc/pam.d/sudo`)

Needed when Auth API accounts should use sudo with a password, which is what
the rule written by [on-demand accounts](#on-demand-accounts) requires. Skip
it if only local accounts use sudo.

sudo has its own PAM stack, separate from sshd's. Add the same line in front
of its authentication lines.

RHEL family:

```text
#%PAM-1.0
auth       [success=done ignore=ignore default=die] pam_rust_oidc.so config=/etc/pam_rust_oidc/config.toml
auth       include      system-auth
...
```

Debian and Ubuntu:

```text
auth       [success=done ignore=ignore default=die] pam_rust_oidc.so config=/etc/pam_rust_oidc/config.toml
@include common-auth
...
```

No reload is needed; PAM reads the file on each use. Afterwards:

- every account sees `[rust-oidc] Password:` and `[rust-oidc] MFA Code:` when
  sudo asks for a password;
- an Auth API account enters its Auth API password and a fresh MFA code. A
  code works once, so right after logging in wait for the next one;
- a local account (`local_users`, system accounts) enters its local password
  and presses Enter at the MFA prompt;
- rules with `NOPASSWD` are not affected, because sudo does not authenticate
  for them;
- scripts that feed sudo a password on standard input (`sudo -S`) must now
  send two lines.

`su` and console logins have their own stacks (`/etc/pam.d/su`,
`/etc/pam.d/login`) and are not changed by any of this.

### 6. SELinux and AppArmor

The module runs inside sshd, so whatever confines sshd confines the module.
What to do depends on the distribution family.

#### RHEL, Rocky, Oracle Linux (SELinux)

Check whether SELinux is enforcing:

```sh
getenforce
```

If it prints `Disabled` or `Permissive`, nothing here is required. If it
prints `Enforcing`, sshd is not allowed to do what the module needs, and
without the steps below logins through the Auth API fail.

1. Install the policy module shipped in this repository,
   [`selinux/pam_rust_oidc.cil`](selinux/pam_rust_oidc.cil):

   ```sh
   semodule -i selinux/pam_rust_oidc.cil
   ```

   It allows three things:

   | Rule | Needed for |
   |---|---|
   | sshd may connect to HTTPS ports | every Auth API login |
   | `useradd` and `userdel` started by sshd run in their own domain (`useradd_t`) | on-demand accounts |
   | sshd may create and remove regular files labelled `etc_t` | the sudo rule in `/etc/sudoers.d` of an on-demand account |

   The file is written for `sshd_session_t`, the domain sshd's PAM stack runs
   in on OpenSSH 9.8 and later (the RHEL 10 family). On older releases the
   domain is `sshd_t`: replace the name throughout the file before installing.
   To see which one applies, run `ps -eZ | grep sshd` while a login is in
   progress, or read the domain from a denial (step 4).

   If you do not use on-demand accounts, the first rule is enough:

   ```sh
   echo '(allow sshd_session_t http_port_t (tcp_socket (name_connect)))' > pam_rust_oidc.cil
   semodule -i pam_rust_oidc.cil
   ```

2. Give the files their labels. A file moved into place from `/tmp` or a home
   directory keeps the label of where it was created, and sshd may then be
   unable to read it:

   ```sh
   restorecon -Rv /usr/lib64/security/pam_rust_oidc.so /etc/pam_rust_oidc \
     /etc/pam.d/sshd /etc/pam.d/sudo /etc/ssh/sshd_config.d /etc/sudoers.d
   ```

3. For on-demand accounts, label the working directory as authentication
   state, which sshd is already allowed to manage:

   ```sh
   semanage fcontext -a -t var_auth_t '/var/lib/pam_rust_oidc(/.*)?'
   install -d -o root -g root -m 0700 /var/lib/pam_rust_oidc
   restorecon -Rv /var/lib/pam_rust_oidc
   ```

   Use the path of `working_dir` if you changed it.

4. If a login still fails, look for denials. Each line names the domain that
   was stopped (`scontext`) and what it tried to reach (`tcontext`):

   ```sh
   ausearch -m avc,user_avc -ts recent --input-logs </dev/null | grep -E 'sshd|useradd'
   ```

   `--input-logs </dev/null` matters when the command is run over ssh or from
   a script; without it `ausearch` waits for input.

sudo needs no rule: it runs in the invoking user's domain, which is not
confined this way. New home directories are created by `mkhomedir_helper`,
which the distribution's policy already lets sshd run.

To undo: `semodule -r pam_rust_oidc` and
`semanage fcontext -d '/var/lib/pam_rust_oidc(/.*)?'`.

What has been verified: on Oracle Linux 10 with SELinux enforcing, an Auth
API login, creating a pending account and deleting an unused one work with
exactly this policy and produce no denials.

#### Debian, Ubuntu (AppArmor)

Nothing is required on a default installation. These distributions use
AppArmor, and sshd is not confined by an AppArmor profile unless an
administrator enabled one. Check:

```sh
aa-status 2>/dev/null | grep -i sshd || echo "sshd is not confined"
```

If that prints a profile name (for example `/usr/sbin/sshd` from the
`apparmor-profiles` package), sshd is confined and the profile must allow what
the module does. Add these to `/etc/apparmor.d/local/usr.sbin.sshd` and reload
with `apparmor_parser -r /etc/apparmor.d/usr.sbin.sshd`:

```text
# pam_rust_oidc
network inet stream,
network inet6 stream,
/etc/pam_rust_oidc/** r,
/usr/lib/@{multiarch}/security/pam_rust_oidc.so mr,

# on-demand accounts
/var/lib/pam_rust_oidc/ rw,
/var/lib/pam_rust_oidc/** rwk,
/etc/sudoers.d/ r,
/etc/sudoers.d/* rw,
/usr/sbin/useradd Ux,
/usr/sbin/userdel Ux,
/usr/sbin/mkhomedir_helper Ux,
/usr/sbin/visudo Ux,
```

Denials are logged by the kernel: `journalctl -k | grep -i apparmor`. This
profile fragment has not been tested, because none of the Debian or Ubuntu
hosts this module runs on confine sshd; treat it as a starting point.

If SELinux is installed on a Debian or Ubuntu host instead, follow the RHEL
section.

### 7. Check before closing your root shell

From a new connection each time:

1. Your usual public-key login still works.
2. The break-glass account logs in with its local password (Enter at the MFA
   prompt) and can run sudo.
3. The prompts read `[rust-oidc] ...`. `[local] Password:` means the module is
   in local-only mode; the auth log (`journalctl -t sshd`, or
   `/var/log/secure`, `/var/log/auth.log`) says why.
4. An Auth API user logs in with password and MFA code.

Failures are logged with the prefix `pam_rust_oidc:`. When the Auth API
refuses a login the module cannot see the reason; the server's audit log has
it.

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

Use the distribution's PAM module directory as the destination (see
[step 1 of the setup](#1-install-the-module)).

## Build

Build on a Linux system with PAM development headers/library installed:

```sh
cargo build --release
```

The shared library is `target/release/libpam_rust_oidc.so`. Install it in the
distribution's PAM module directory (see
[step 1 of the setup](#1-install-the-module)). There is no prebuilt ARM64
module; build it on the host.

The module logs only generic configuration/network failure descriptions to the
auth log. It never logs users' passwords, OTPs, application secrets, client
assertions, or access tokens. Requests have a 15-second timeout and fail closed.
Proxy environment variables are ignored. Secrets are wiped from the module's
own buffers on a best-effort basis; copies inside the HTTP and TLS libraries
are not.

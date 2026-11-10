# ssshhh-env

**Stop sending `.env` files on Slack. `ssh` pull them instead.**

ssshhh-env is a self-hosted SSH server that lets a small team store, share and version its `.env` files. Teammates use the `ssh` client they already have, so there is nothing to install on their machines. Their SSH key is their identity, and you add a teammate by their GitHub username.

> **Status: early development. Not usable yet.** The commands below show the planned interface. Don't store real secrets in it until v0.1 is released.

## Planned usage

```bash
# Team lead, once
cat .env | ssh envs.myteam.dev push myapp
ssh envs.myteam.dev grant myapp @rahul @priya      # fetches and pins their GitHub keys

# Any teammate
ssh envs.myteam.dev pull myapp > .env
ssh envs.myteam.dev pull myapp:prod > .env.prod     # per-environment

# Day to day
ssh envs.myteam.dev history myapp                   # who changed what, and when
ssh envs.myteam.dev diff myapp 6 7                  # key names only, never values
ssh envs.myteam.dev revoke myapp @amit              # access removed immediately
```

## Why

Small teams usually share secrets through chat, where they stay in history forever, go stale after a rotation, and stay with people after they leave. Tools like Vault, Infisical and Doppler solve this, but they're heavy to run or need a client on every machine. ssshhh-env aims to be the smallest thing that fixes it:

- **Zero client install.** If you have `ssh`, you're a user.
- **No accounts or passwords.** An SSH public key is the identity.
- **Self-hosted.** Secrets stay on infrastructure you control.
- **Secure by default.** Access is denied unless it's granted, data is encrypted at rest, and secrets are never logged.
- **Boring to run.** One static binary or Docker image, plus one SQLite file.

It is meant for teams of about 2 to 20 people. Organisations with compliance requirements should use Vault or a cloud secrets manager.

## Trust model

- Each project's secrets are encrypted at rest with XChaCha20-Poly1305 under a per-project key. Those keys are wrapped by a master key that is never stored in the database, so a stolen database file or backup is useless on its own.
- The server decrypts secrets in order to serve them over SSH. **Anyone with root on the server, or with the master key, can read the secrets.** That trade-off is what makes zero-install possible. Run the server on infrastructure you trust.
- Only public-key authentication is accepted. There is no shell, no SFTP and no port forwarding.
- A teammate's GitHub keys are fetched once, when they are granted access, and then pinned. Later changes to their GitHub account don't grant anything new.
- Once a secret has been pulled to a laptop, it is outside the server's control. After you revoke someone, rotate the secrets they had access to.
- Every action is recorded in an audit log, including reads. Secret values are never written to logs, diffs or audit entries.

An optional end-to-end mode, where the server cannot read secrets, is on the roadmap. It would need a small client.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Development

Requires Go 1.26.8 or later.

With Nix (flakes):

```bash
nix develop        # Go, gopls, staticcheck, govulncheck, gosec, sqlite
go build ./...
go test -race ./...
```

Without Nix, install Go and use the same `go` commands.

To run the server locally, create the first admin from your own public key, then start it:

```bash
go build -o ssshhh-env ./cmd/ssshhh-env
./ssshhh-env admin bootstrap --name "$USER" --key ~/.ssh/id_ed25519.pub   # or: --github <username>
./ssshhh-env serve                     # listens on :2222, prints the host key fingerprint

ssh -p 2222 localhost whoami
```

`admin bootstrap` only works on the host and only while there are no users, so nobody can claim admin over the network. Everything lives in `data/` (mode `0700`): the SQLite database `ssshhh.db` and the host key. Every session and every failed login is recorded in the audit log:

```bash
sqlite3 -header -column data/ssshhh.db 'SELECT ts, user_id, remote_addr, action, result FROM audit_log'
```

## License

[Apache-2.0](LICENSE)

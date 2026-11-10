# ssshhh-env

**Stop sending `.env` files on Slack. `ssh` pull them instead.**

ssshhh-env is a self-hosted SSH server that lets a small team store, share and version its `.env` files. Teammates use the `ssh` client they already have, so there is nothing to install on their machines. Their SSH key is their identity, and you add a teammate by their GitHub username.

```bash
# Team lead
cat .env | ssh envs push myapp -m "add stripe key"
ssh envs grant myapp @rahul                   # fetches and pins their GitHub keys
ssh envs grant myapp @priya --role writer

# Any teammate
ssh envs pull myapp > .env
ssh envs pull myapp:prod > .env.prod          # one project, several environments

# Day to day
ssh envs history myapp                        # who changed what, and when
ssh envs diff myapp 6 7                       # variable names only, never values
ssh envs revoke myapp @amit                   # access removed immediately
```

![Pushing a .env file, granting a teammate, pulling it back and viewing the history over ssh](demo.gif)

> **Status: v0.1, early.** It works and is tested, but it is young and the cryptography has not had an independent review yet. Read [Trust model and limits](#trust-model-and-limits) before you put production secrets in it.

## Why

Small teams usually share secrets through chat, where they stay in history forever, go stale after a rotation, and stay with people after they leave. Tools like Vault, Infisical and Doppler solve this, but they're heavy to run or need a client on every machine. ssshhh-env aims to be the smallest thing that fixes it:

- **Zero client install.** If you have `ssh`, you're a user.
- **No accounts or passwords.** An SSH public key is the identity.
- **Self-hosted.** Secrets stay on infrastructure you control.
- **Secure by default.** Access is denied unless it's granted, data is encrypted at rest, and secrets are never logged.
- **Boring to run.** One static binary or Docker image, plus one SQLite file.

It is meant for teams of about 2 to 20 people. Organisations with compliance requirements should use Vault or a cloud secrets manager.

## Quickstart

This runs the server on your own machine and pulls a secret from it. It takes a few minutes. You need an SSH key (`ls ~/.ssh/*.pub`; if there is none, run `ssh-keygen -t ed25519`).

### 1. Get the binary

Releases have binaries for Linux and macOS (amd64 and arm64). Replace `linux_amd64` with your platform:

```bash
curl -fsSLO https://github.com/lodgingzeus/ssshhh-env/releases/latest/download/ssshhh-env_linux_amd64.tar.gz
curl -fsSLO https://github.com/lodgingzeus/ssshhh-env/releases/latest/download/checksums.txt
sha256sum --ignore-missing -c checksums.txt        # macOS: shasum -a 256 --ignore-missing -c checksums.txt
tar -xzf ssshhh-env_linux_amd64.tar.gz ssshhh-env
```

Or build it with Go 1.26.8 or later: `go install github.com/lodgingzeus/ssshhh-env/cmd/ssshhh-env@latest`.

Each release archive also has a signed build provenance attestation. With the GitHub CLI you can check that it was built from this repository: `gh attestation verify ssshhh-env_linux_amd64.tar.gz --repo lodgingzeus/ssshhh-env`.

### 2. Set up and start the server

```bash
./ssshhh-env admin bootstrap --name "$USER" --key ~/.ssh/id_ed25519.pub   # or: --github <your-github-username>
./ssshhh-env keygen-master --out ~/ssshhh-master.key                      # created with mode 0600
./ssshhh-env serve --master-key-file ~/ssshhh-master.key
```

- `admin bootstrap` creates the first admin. It only works on the host and only while there are no users, so nobody can claim admin over the network.
- `keygen-master` creates the **master key**, which encrypts everything in the database. Keep it out of the data directory and back it up (see [Backups](#backups-and-the-master-key)). Until you do, `serve` prints a warning at startup.
- `serve` listens on port 2222 and keeps its database and host key in `./data` (mode `0700`). It prints the server's host key fingerprint, like `host_key=SHA256:...`.

### 3. Use it

In another terminal:

```bash
ssh -p 2222 localhost whoami          # first time: check the fingerprint matches what serve printed, then type yes
ssh -p 2222 localhost init myapp      # server admins only; you become the owner

printf 'API_KEY=hunter2\nDATABASE_URL="postgres://localhost/app"\n' > demo.env
ssh -p 2222 localhost push myapp < demo.env
ssh -p 2222 localhost pull myapp      # prints the file back
ssh -p 2222 localhost history myapp
```

That's it. To share it with your team, run the server somewhere they can reach (see [Deploying safely](#deploying-safely)) and grant them access.

### Run with Docker

The image is `ghcr.io/lodgingzeus/ssshhh-env` (linux/amd64 and linux/arm64). It runs as a non-root user and works with a read-only root filesystem. The commands below keep the data and the master key in the current directory, owned by you:

```bash
IMAGE=ghcr.io/lodgingzeus/ssshhh-env:latest
mkdir -m 700 ssshhh-data
(umask 077; docker run --rm "$IMAGE" keygen-master > master.key)

docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/ssshhh-data:/data" \
  -v "$HOME/.ssh/id_ed25519.pub:/key.pub:ro" "$IMAGE" admin bootstrap --name "$USER" --key /key.pub

docker run -d --name ssshhh-env --restart unless-stopped \
  --user "$(id -u):$(id -g)" --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges \
  -p 2222:2222 \
  -v "$PWD/ssshhh-data:/data" \
  -v "$PWD/master.key:/run/secrets/master.key:ro" \
  "$IMAGE" serve --data-dir /data --master-key-file /run/secrets/master.key

docker logs ssshhh-env                 # shows the host key fingerprint
ssh -p 2222 localhost whoami
```

Once you have backed up `master.key` (see [Backups](#backups-and-the-master-key)), stop the startup warning with:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/ssshhh-data:/data" \
  -v "$PWD/master.key:/run/secrets/master.key:ro" "$IMAGE" \
  admin confirm-backup --data-dir /data --master-key-file /run/secrets/master.key
```

The same setup as a Compose file is in [compose.yaml](compose.yaml): `SSSHHH_UID=$(id -u) SSSHHH_GID=$(id -g) docker compose up -d`.

The container runs as your user (`--user`) so it can read `master.key` and `ssshhh-data` while both stay private to you. If you run it as the image's default user (uid 65532) instead, `chown 65532` both. Instead of a file, the key can be passed in the `SSSHHH_MASTER_KEY` environment variable, but then `docker inspect` shows it.

## Using it

### Connecting

Add the server to `~/.ssh/config` so the commands stay short:

```
Host envs
    HostName envs.example.com
    Port 2222
```

The first time you connect, `ssh` shows the server's host key fingerprint. Compare it with the one your admin published (it's printed when the server starts) before you type `yes`. That check is what protects you from a server pretending to be yours.

### Commands

`<project[:env]>` is a project name, optionally with an environment: `myapp` is `myapp:default`, and `myapp:prod` is the `prod` environment. Environments are created by their first `push`. Names are lowercase letters, digits and `-`.

| Command | Who can run it | What it does |
|---|---|---|
| `whoami` | anyone | your user, key fingerprint and role in each project |
| `projects` | anyone | projects you are a member of |
| `init <project>` | server admins | create a project; you become its owner |
| `pull <project[:env]> [--version N]` | reader | print the latest `.env`, or version N |
| `history <project[:env]> [--limit N]` | reader | versions, newest first: author, message, names added and removed |
| `diff <project[:env]> <a> <b>` | reader | variable names added, removed or changed between two versions |
| `members <project>` | reader | who has which role |
| `push <project[:env]> [-m message]` | writer | store the `.env` file on stdin as a new version |
| `grant <project> <user\|@github-user> [--role r]` | owner | give access (`reader` by default, or `writer`, `owner`); `--role` on an existing member changes their role |
| `revoke <project> <user\|@github-user>` | owner | take access away (a project always keeps at least one owner) |
| `help` | anyone | list the commands |

Roles include everything below them: an owner can do what a writer can, and a writer what a reader can. Being a server admin does **not** give access to a project's secrets; admins need to be granted access like anyone else.

Server admins also manage accounts:

| Command | What it does |
|---|---|
| `user add <name> [--github <login>]` | add a user, with public keys from stdin or from GitHub |
| `user list` | list users |
| `user disable <name>` | disable a user; their keys stop working immediately |
| `key list <user>` | list a user's keys and when each was last used |
| `key add <user>` | add public keys from stdin |
| `key remove <user> <fingerprint>` | remove one key |
| `key refresh <user>` | re-fetch a user's keys from GitHub |

```bash
ssh envs user add sam < sam_ed25519.pub
ssh envs key refresh rahul
```

### Adding teammates

`grant myapp @rahul` fetches `https://github.com/rahul.keys`, creates the user `rahul` if needed, and prints the fingerprints it is about to trust. **Those keys are pinned:** if someone later adds a key to that GitHub account, it gets no access until an admin runs `key refresh rahul`. Ask your teammate to compare the fingerprints with `ssh-keygen -lf ~/.ssh/id_ed25519.pub`.

Without GitHub, an admin adds the user and their public key with `user add`, and an owner grants them with `grant myapp sam`.

Accepted keys: ed25519, ECDSA, FIDO hardware keys (`sk-ssh-ed25519`, `sk-ecdsa`), and RSA of 3072 bits or more. DSA and shorter RSA keys are refused.

### When someone leaves

```bash
ssh envs revoke myapp @amit        # this project
ssh envs user disable amit         # every project (admins)
```

Both take effect immediately, including for open connections. **Then rotate the secrets they had.** Revoking stops future pulls; it can't make anyone forget what they already pulled. `revoke` and `user disable` list what to rotate.

### What gets stored

A pushed file must be `KEY=VALUE` lines, `#` comments and blank lines, optionally with `export` in front; quoted values may span lines. It is stored exactly as sent, at most 256 KB. Files that aren't valid UTF-8, contain NUL bytes, start with a byte-order mark, repeat a variable or have no variables are refused, with a line number and the reason, but never the content.

Every push makes a new version. Versions are never changed or deleted, so `pull --version N` always gives back exactly what was pushed as version N.

## Trust model and limits

What ssshhh-env protects:

- **A stolen database or backup.** Each project's secrets are encrypted with XChaCha20-Poly1305 under a per-project key, and those keys are wrapped by a master key that is never stored in the database. Each version is bound to its project, environment and version number, so encrypted rows can't be swapped around.
- **Unauthorised pulls.** Only registered public keys can log in; there are no passwords. Every command is checked against the caller's role in the project, and anything not explicitly allowed is refused.
- **A hijacked GitHub account.** GitHub keys are fetched once, at grant time, and pinned.
- **Abuse of the SSH server.** There is no shell, no SFTP, no port forwarding, and no agent or X11 forwarding. Connections are rate-limited per IP and have idle and total time limits.
- **Leaks through logs.** Secret values never appear in logs, error messages, `diff` or `history` output, or the audit log. Names and messages shown to other users have terminal control characters stripped.
- **Silent changes.** Every action is recorded in an append-only audit log, including every `pull` and every failed login. A `pull` is logged before the secret is sent; if the log can't be written, nothing is sent.

What it does **not** protect against:

- **Root on the server, or the master key with the database.** The server decrypts secrets in order to serve them over SSH. That trade-off is what makes zero-install possible. Run it on infrastructure you trust.
- **A compromised teammate laptop.** Their SSH key is their identity. Hardware (`sk-`) keys reduce this risk.
- **Secrets after they are pulled.** Once a `.env` is on a laptop, it's outside the server's control.
- **Memory.** Go can't reliably wipe memory. Plaintext is kept short-lived, but not zeroised.

An optional end-to-end mode, where the server cannot read secrets, is on the roadmap. It would need a small client.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Deploying safely

- **Run it as an unprivileged user**, never as root. The Docker image already does, with a read-only root filesystem.
- **Keep files private.** The server refuses to start if the data directory isn't `0700`, or if the database or master key file can be read by anyone else.
- **Publish the host key fingerprint** (printed by `serve` at startup) to your team, in your README or wiki. Better still, publish a ready `known_hosts` line, so nobody has to compare by eye: get it with `ssh-keyscan -p 2222 envs.example.com`, and check it with `ssh-keygen -lf` against the fingerprint `serve` printed.
- **Port:** use 2222 plus the `~/.ssh/config` entry above. Use port 22 only if you move the host's real `sshd` elsewhere.
- **Restrict who can connect**, with a firewall or VPN, if you can. Public-key auth is the real gate, but there's no reason to expose it to the whole internet.
- **Keep it updated.** Releases list security fixes.

## Backups and the master key

The data directory holds the database (`ssshhh.db`) and the server's host key. The master key lives elsewhere.

- **Back up the master key separately from the database.** A backup that holds both is as good as unencrypted. One that holds only the database is useless without the key.
- **If the master key is lost, the secrets are gone.** Nobody can recover them.
- Once the key is backed up, tell the server, and the startup warning stops:

  ```bash
  ./ssshhh-env admin confirm-backup --master-key-file ~/ssshhh-master.key
  ```

- Back up the database with SQLite's online backup while the server runs, keeping the copy private: `(umask 077; sqlite3 data/ssshhh.db ".backup ssshhh-backup.db")`. To restore, stop the server and put the copy back as `data/ssshhh.db` (mode `0600`).
- The server refuses to start with a master key that doesn't match the database, so a mixed-up key shows up at startup and not as failed pulls.

## Audit log

Every session, every command and every failed login is in the `audit_log` table:

```bash
sqlite3 -header -column data/ssshhh.db \
  'SELECT ts, user_id, remote_addr, action, target, result, detail FROM audit_log ORDER BY id DESC LIMIT 50'
```

Rows can't be updated or deleted through the database, and they never contain secret values.

## Development

Requires Go 1.26.8 or later.

```bash
nix develop        # optional: Go, gopls, staticcheck, govulncheck, gosec, sqlite
go build ./...
go test -race ./...
go build -o ssshhh-env ./cmd/ssshhh-env
```

CI also runs `staticcheck`, `gosec`, `govulncheck`, short fuzzing runs of the `.env` and command-line parsers, and a Docker build. Releases are built by GoReleaser from a version tag ([.goreleaser.yaml](.goreleaser.yaml)); `goreleaser release --snapshot --clean` does a local dry run.

The demo GIF is recorded with [VHS](https://github.com/charmbracelet/vhs) from [demo.tape](demo.tape), which starts its own throwaway server.

## License

[Apache-2.0](LICENSE)

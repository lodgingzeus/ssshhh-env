# Records demo.gif for the README:
#
#   go build -o ssshhh-env ./cmd/ssshhh-env && PATH="$PWD:$PATH" vhs demo.tape
#
# The hidden setup starts a throwaway server in a temporary directory on
# 127.0.0.1:2222 and points `ssh envs` at it through a private ssh config.
# Nothing in ~/.ssh is read or changed.

Output demo.gif

Require ssh
Require ssh-keygen
Require ssshhh-env

Set Shell bash
Set FontSize 18
Set Width 1100
Set Height 600
Set Padding 20
Set TypingSpeed 45ms

Hide
Type `export D=$(mktemp -d) && cd "$D" && export PS1='$ '` Enter
Type `ssh-keygen -q -t ed25519 -N '' -f id -C demo && ssh-keygen -q -t ed25519 -N '' -f rahul -C rahul` Enter
Type `ssshhh-env admin bootstrap --name you --key id.pub >/dev/null && ssshhh-env keygen-master --out mk 2>/dev/null` Enter
Type `(ssshhh-env serve --addr 127.0.0.1:2222 --master-key-file mk >/dev/null 2>&1 &) ; sleep 1` Enter
Type `printf 'Host envs\n HostName 127.0.0.1\n Port 2222\n IdentityFile %s/id\n IdentitiesOnly yes\n UserKnownHostsFile %s/kh\n StrictHostKeyChecking accept-new\n LogLevel ERROR\n' "$D" "$D" > cfg` Enter
Type `ssh() { command ssh -F "$D/cfg" "$@"; }` Enter
Type `ssh envs init myapp >/dev/null; sleep 1; ssh envs user add rahul < rahul.pub >/dev/null; sleep 1` Enter
Type `printf 'API_KEY=sk_test_51Hx\nDATABASE_URL="postgres://db.internal/app"\nREDIS_URL=redis://cache:6379\n' > .env` Enter
Sleep 1.5s
Type "clear" Enter
Show

Type "cat .env" Enter
Sleep 1.5s

Type "ssh envs push myapp -m 'initial import' < .env" Enter
Sleep 2s

Type "ssh envs grant myapp rahul" Enter
Sleep 2s

Type "ssh envs pull myapp" Enter
Sleep 2s

Type "ssh envs history myapp" Enter
Sleep 3s

Hide
Type `pkill -f "serve --addr 127.0.0.1:2222 --master-key-file mk"; rm -rf "$D"` Enter

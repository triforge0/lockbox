# lockbox

A minimal, secure, cross-platform CLI password manager written in Go.

Credentials are stored in a single encrypted file under `~/.lockbox/` (the
default vault is `store.vault`). There is no database and no network access —
just one local, encrypted blob.

You can keep several independent vaults side by side with the global
`--vault <name>`/`-V` flag. Each named vault is a separate file with its own
master password and its own session, so unlocking one never decrypts another.

## Security

- The encryption key is derived from your master password with **Argon2id**
  (64 MiB, 3 passes, 4 lanes). Older vaults written with 1 pass are transparently
  re-keyed to the stronger parameters the next time you unlock them.
- The vault is encrypted as a single blob with **AES-256-GCM**.
- Plaintext is never written to disk. The vault file is `0600`.
- The salt is fixed for the life of the vault; each save uses a fresh nonce.
- The master password is read without echoing to the terminal.
- The agent only takes orders from another process running the same `lockbox`
  binary, so other local processes (even same-user) can't ask it to decrypt.

## Sessions

To avoid re-typing the master password on every command, `lockbox` uses an
in-memory session backed by a background agent:

- `lockbox unlock` prompts for the master password, derives the key, and starts
  a detached agent that holds the **key in memory** (never on disk) and serves
  encrypt/decrypt requests over a per-vault Unix-domain socket (`0600`) under
  `~/.lockbox/` (`agent.sock` for the default vault). The key is passed to the
  agent over a pipe — never via the command line and never written to disk.
- `add`, `get`, `list`, and `delete` require an active session. If none exists
  (or it has expired), they tell you to run `lockbox unlock`.
- The session auto-locks after **15 minutes** of inactivity (each command
  resets the timer), capped at an absolute **24 hours**; when it expires the
  agent self-destructs and wipes the key.
- `lockbox status` shows whether the vault is unlocked and when it will lock;
  `lockbox lock` ends the session immediately.

## Install

### Homebrew (macOS)

```sh
brew install triforge0/tap/lockbox
```

### Pre-built binaries

Download an archive for your OS/arch from the
[releases page](https://github.com/triforge0/lockbox/releases) and put `lockbox`
on your `PATH`. (Linux and Windows builds are published there too.)

### From source

```sh
go install ./cmd/lockbox   # installs the `lockbox` binary to $GOBIN
```

Or build a standalone binary:

```sh
go build -o lockbox ./cmd/lockbox
```

Cross-compile, e.g. for Windows:

```sh
GOOS=windows GOARCH=amd64 go build -o lockbox.exe ./cmd/lockbox
```

## Layout

```
cmd/lockbox/      entry point (dispatch only)
internal/
  cli/            commands, prompts, argument dispatch
  model/          Vault / Item types
  crypto/         Argon2id + AES-256-GCM + password generation
  totp/           RFC 6238 time-based one-time passwords (2FA)
  storage/        on-disk envelope + ~/.lockbox paths
  agent/          the in-memory session: daemon, socket IPC, spawn, peer-auth
```

## Usage

```sh
lockbox init                # create a new empty encrypted vault
lockbox unlock              # start a session (prompts for master password)
lockbox add <service>       # add credentials (username, password, optional 2FA)
lockbox edit <service>      # update a service (blank input keeps current value)
lockbox get <service>       # print credentials for a service
lockbox get <service> -p    # print only the password (pipe-friendly, no newline)
lockbox list                # list all stored service names
lockbox list -l             # list services with usernames and a 2FA column
lockbox search <query>      # find services by name or username
lockbox totp <service>      # print the current 2FA code for a service
lockbox delete <service>    # remove a service (asks to confirm; -f to skip)
lockbox change-password     # change the master password (re-encrypts the vault)
lockbox status              # show whether the vault is unlocked
lockbox lock                # end the session immediately
lockbox vaults              # list all vaults and whether each is unlocked
lockbox export -o out.json  # export the vault as plaintext JSON (asks to confirm)
lockbox import in.json      # merge items from a JSON file (--overwrite to replace)
lockbox gen [length]        # generate a random password (default length 20)
```

Use a named vault with the global `--vault`/`-V` flag (it can appear anywhere):

```sh
lockbox --vault work init
lockbox -V work unlock
lockbox -V work add github
```

Typical flow:

```sh
lockbox init
lockbox unlock
lockbox add github
lockbox get github -p | pbcopy   # copy the password to the clipboard
lockbox lock
```

There is no recovery if you forget the master password — by design.

## File format

```json
{
  "version": 2,
  "salt": "...base64...",
  "nonce": "...base64...",
  "ciphertext": "...base64..."
}
```

`ciphertext` is the AES-256-GCM encryption of the vault's JSON representation
(`{"items":[{"service","username","password","totp"?}, ...]}`); `totp` is an
optional base32 2FA seed and is omitted for items without one. Version 1 vaults
(1-pass Argon2id) are still readable and are upgraded to version 2 on the next
unlock. `change-password` re-encrypts the vault under a new key and is the one
operation besides `init` that mints a fresh salt; it ends any running session.

## Releasing

CI (`.github/workflows/ci.yml`) runs `gofmt`/`go vet`/`go test` on every push and
PR across Linux, macOS, and Windows. Releases are automated with
[GoReleaser](https://goreleaser.com) (`.goreleaser.yaml`).

One-time setup for the Homebrew tap:

1. Create a public repo `triforge0/homebrew-tap`.
2. Create a GitHub Personal Access Token with `repo` scope (classic) — or a
   fine-grained token with **Contents: read/write** on that tap repo.
3. In this repo's settings add it as an Actions secret named
   `HOMEBREW_TAP_GITHUB_TOKEN`.

Cut a release by pushing a tag:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The release workflow builds all platforms, publishes a GitHub Release with
archives + `checksums.txt`, and pushes the cask to the tap. Dry-run locally with:

```sh
goreleaser release --snapshot --clean --skip=publish
```

## Notes

- The Unix-domain socket path is subject to the OS limit (~104 chars on macOS).
  The default `~/.lockbox/agent.sock` is well within it; an unusually long home
  directory could exceed it.
- On some macOS toolchain versions Go's internal linker omits `LC_UUID`, which
  newer dyld rejects. If a freshly built binary aborts on launch, build with the
  external linker and ad-hoc sign:
  `go build -ldflags=-linkmode=external -o lockbox ./cmd/lockbox && codesign -s - -f lockbox`.

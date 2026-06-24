# lockbox

A minimal, secure, cross-platform CLI password manager written in Go.

Credentials are stored in a single encrypted file at `~/.lockbox/store.vault`.
There is no database and no network access — just one local, encrypted blob.

## Security

- The encryption key is derived from your master password with **Argon2id**
  (64 MiB, 1 pass, 4 lanes).
- The vault is encrypted as a single blob with **AES-256-GCM**.
- Plaintext is never written to disk. The vault file is `0600`.
- The salt is fixed for the life of the vault; each save uses a fresh nonce.
- The master password is read without echoing to the terminal.

## Sessions

To avoid re-typing the master password on every command, `lockbox` uses an
in-memory session backed by a background agent:

- `lockbox unlock` prompts for the master password, derives the key, and starts
  a detached agent that holds the **key in memory** (never on disk) and serves
  encrypt/decrypt requests over a Unix-domain socket at `~/.lockbox/agent.sock`
  (`0600`). The key is passed to the agent over a pipe — never via the command
  line and never written to disk.
- `add`, `get`, `list`, and `delete` require an active session. If none exists
  (or it has expired), they tell you to run `lockbox unlock`.
- The session expires automatically **24 hours** after unlock; the agent
  self-destructs and wipes the key.
- `lockbox lock` ends the session immediately.

## Install

```sh
go install   # from this directory, installs the `lockbox` binary to $GOBIN
```

Or build a standalone binary:

```sh
go build -o lockbox .
```

Cross-compile, e.g. for Windows:

```sh
GOOS=windows GOARCH=amd64 go build -o lockbox.exe .
```

## Usage

```sh
lockbox init                # create a new empty encrypted vault
lockbox unlock              # start a 24h session (prompts for master password)
lockbox add <service>       # add credentials (prompts for username + password)
lockbox get <service>       # print credentials for a service
lockbox list                # list all stored service names
lockbox delete <service>    # remove a service
lockbox lock                # end the session immediately
```

Typical flow:

```sh
lockbox init
lockbox unlock
lockbox add github
lockbox get github
lockbox lock
```

There is no recovery if you forget the master password — by design.

## File format

```json
{
  "version": 1,
  "salt": "...base64...",
  "nonce": "...base64...",
  "ciphertext": "...base64..."
}
```

`ciphertext` is the AES-256-GCM encryption of the vault's JSON representation
(`{"items":[{"service","username","password"}, ...]}`).

## Notes

- The Unix-domain socket path is subject to the OS limit (~104 chars on macOS).
  The default `~/.lockbox/agent.sock` is well within it; an unusually long home
  directory could exceed it.
- On some macOS toolchain versions Go's internal linker omits `LC_UUID`, which
  newer dyld rejects. If a freshly built binary aborts on launch, build with the
  external linker and ad-hoc sign:
  `go build -ldflags=-linkmode=external -o lockbox . && codesign -s - -f lockbox`.

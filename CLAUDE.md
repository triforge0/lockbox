# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
go build -o lockbox .                  # build the CLI binary
go test ./...                          # run all tests
go test -run TestAgentExpired ./...    # run a single test by name
go vet ./...                           # static checks
GOOS=windows GOARCH=amd64 go build -o lockbox.exe .   # cross-compile
```

There is no separate lint config; `go vet` plus `gofmt` are the bar.

macOS toolchain note: on some Go/macOS combinations the internal linker omits
`LC_UUID` and dyld aborts the binary (SIGABRT 134) or an externally-linked
binary fails its signature (SIGKILL 137). If a built binary won't run locally,
use: `go build -ldflags=-linkmode=external -o lockbox . && codesign -s - -f lockbox`
(and add `-ldflags=-linkmode=external` to `go test`). This is environment-only;
the code is unaffected.

## Architecture

`lockbox` is a single-package (`package main`) CLI password manager. The whole
data store is one AES-256-GCM-encrypted blob at `~/.lockbox/store.vault`; there
is no database, no network, and no per-item encryption.

### The session model is the defining design decision

A CLI process exits after each command, so "keep the key in memory across
commands" is implemented with a **background agent daemon**:

- `lockbox unlock` verifies the master password, then re-execs the same binary
  as a hidden `__agent` subcommand (`spawn.go`). The derived key + vault salt
  are handed to the agent over a **stdin pipe** — never via argv, never to disk.
  The agent (`agent.go`) holds the key in memory, listens on a Unix-domain
  socket `~/.lockbox/agent.sock` (`0600`), and self-destructs after 24h
  (`sessionTTL`), wiping the key.
- `add`/`get`/`list`/`delete` never prompt for a password. They connect to the
  agent and ask it to **encrypt/decrypt raw blobs**, so the key never leaves the
  agent process. No agent or an expired one surfaces as `errNoSession`
  ("run lockbox unlock").
- `lock` tells the agent to exit and remove the socket.

### Crypto consequence of sessions (important invariant)

Because the agent holds a *derived key*, not the password, it cannot re-derive
against a new salt. So **the salt is fixed at `init` for the vault's lifetime**;
each save reuses the salt and generates only a fresh nonce. Do not reintroduce
per-save salt regeneration — it would break every existing session/agent.

### Files

- `vault.go` — data model (`Vault`/`Item`), on-disk envelope (`vaultFile`),
  Argon2id `deriveKey`, raw `gcmEncrypt`/`gcmDecrypt` (operate on bytes so the
  agent needn't know the JSON shape), envelope encode/`decode`, and atomic
  `0600` file I/O.
- `agent.go` — the agent server (`runAgent`, `agent.handle`), the request/
  response protocol (newline-delimited JSON, base64 payloads), and the client
  helpers (`agentCall`, `agentAlive`, `agentEncrypt`, `agentDecrypt`).
- `spawn.go` — launches the detached agent and performs the stdin handshake.
- `detach_unix.go` / `detach_windows.go` — build-tagged `detachSysProcAttr()`
  (setsid on Unix; DETACHED_PROCESS on Windows). The only platform-specific code.
- `commands.go` — one `cmdX` per subcommand plus `openVault`/`saveVault` (the
  decrypt-via-agent / encrypt-via-agent helpers).
- `prompt.go` — terminal input. `readSecret` reads without echo via
  `golang.org/x/term`, falling back to a plain read when stdin is not a TTY
  (this is what makes piped/scripted input and tests work). **All stdin reads
  share the single package-level `stdin` buffered reader** — do not create new
  `bufio.Reader`s on `os.Stdin`, or buffered bytes past the first line get
  silently dropped between prompts.
- `main.go` — arg dispatch and usage. Misuse returns a `*usageErr` (via
  `usageError(...)`), which `main` detects with `errors.As` to print usage. The
  hidden `__agent` command must stay routed here.

## Conventions / gotchas

- Dependencies are intentionally minimal: stdlib plus `golang.org/x/crypto`
  (Argon2id) and `golang.org/x/term` (no-echo input). Keep it that way.
- Crypto parameters and the file `version` are constants in `vault.go`. Any
  incompatible format/KDF change must bump `vaultFileVersion` and handle the old
  version in `decode`.
- `cmdInit` refuses to overwrite an existing vault; `cmdAdd` rejects duplicate
  services. Preserve these guards — there is no undo and no password recovery.
- Unix-socket paths are limited (~104 chars on macOS). The default home-based
  path is fine; tests that set a long `$HOME` will fail to bind the socket. Use a
  short `$HOME` (e.g. `/tmp/lbh`) when running the binary end-to-end in tests.
- The 24h expiry can't be waited out in tests; `agent_test.go` exercises
  `agent.handle` directly over `net.Pipe` with a past `expiresAt`.

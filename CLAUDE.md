# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
go build -o lockbox ./cmd/lockbox             # build the CLI binary
go test ./...                                 # run all tests
go test ./internal/agent -run TestAgentLock   # run a single test by name
go vet ./...                                   # static checks
GOOS=windows GOARCH=amd64 go build -o lockbox.exe ./cmd/lockbox   # cross-compile
```

There is no separate lint config; `go vet` plus `gofmt` are the bar. CI
(`.github/workflows/ci.yml`) enforces `gofmt -l`, `go vet`, and `go test` on
Linux/macOS/Windows.

## Releasing

Tag `v*` triggers `.github/workflows/release.yml`, which runs GoReleaser
(`.goreleaser.yaml`) on ubuntu: cross-builds 6 targets, publishes a GitHub
Release with archives + `checksums.txt`, and pushes a Homebrew **cask** to
`triforge0/homebrew-tap` (needs the `HOMEBREW_TAP_GITHUB_TOKEN` secret). Validate
config with `goreleaser check`; dry-run with
`goreleaser release --snapshot --clean --skip=publish`.

- The version string is injected via `-ldflags -X lockbox/internal/cli.version`
  (the `version` command / `--version` flag print it; default `dev`).
- GoReleaser deprecated `brews`/formulae, so we ship a cask (macOS-only); Linux
  users use the tarballs or `go install`. The cask's `postflight` strips the
  Gatekeeper quarantine xattr because the binary is only ad-hoc signed.
- Release builds must use Go ≥1.23 (the runner's `stable`) so darwin binaries get
  `LC_UUID` + an ad-hoc signature; Go 1.22.x omits `LC_UUID` and the binary
  aborts on recent macOS.

macOS toolchain note: on some Go/macOS combinations the internal linker omits
`LC_UUID` and dyld aborts the binary (SIGABRT 134) or an externally-linked
binary fails its signature (SIGKILL 137). If a built binary won't run locally,
use: `go build -ldflags=-linkmode=external -o lockbox ./cmd/lockbox && codesign -s - -f lockbox`
(and add `-ldflags=-linkmode=external` to `go test`). This is environment-only;
the code is unaffected.

## Architecture

`lockbox` is a CLI password manager. The whole data store is one
AES-256-GCM-encrypted blob at `~/.lockbox/store.vault`; there is no database, no
network, and no per-item encryption.

Layered into `cmd/` + `internal/` packages with a strict, acyclic dependency
graph — keep it that way:

```
model/    Vault/Item types                      (no deps)
crypto/   Argon2id DeriveKey/NewSalt, AES-GCM    (no deps)
storage/  VaultFile envelope, load/save, paths   (no deps)
agent/    the session daemon + client + spawn    (deps: crypto, storage)
cli/      commands, prompts, dispatch            (deps: model, crypto, storage, agent)
cmd/lockbox/main.go  -> cli.Execute(os.Args[1:]) (deps: cli)
```

crypto/model/storage are leaves and must not import each other or higher layers.

### The session model is the defining design decision

A CLI process exits after each command, so "keep the key in memory across
commands" is implemented with a **background agent daemon**:

- `lockbox unlock` verifies the master password, then re-execs the same binary
  as a hidden `__agent` subcommand (`agent/spawn.go`, `agent.Spawn`). The derived
  key + vault salt are handed to the agent over a **stdin pipe** — never via
  argv, never to disk. The agent (`agent/server.go`, `agent.Run`) holds the key
  in memory, listens on a Unix-domain socket `~/.lockbox/agent.sock` (`0600`),
  and self-destructs after 24h (`agent.SessionTTL`), wiping the key.
- `add`/`get`/`list`/`delete` never prompt for a password. The cli layer calls
  `agent.Encrypt`/`agent.Decrypt` (`agent/client.go`), which ask the daemon to
  process **raw blobs**, so the key never leaves the agent process. No agent or
  an expired one surfaces as `agent.ErrNoSession` ("run lockbox unlock").
- `lock` calls `agent.Lock`, telling the daemon to exit and remove the socket.

### Crypto consequence of sessions (important invariant)

Because the agent holds a *derived key*, not the password, it cannot re-derive
against a new salt. So **the salt is fixed at `init` for the vault's lifetime**
(`storage.VaultFile.Salt`); each save reuses the salt and generates only a fresh
nonce. Do not reintroduce per-save salt regeneration — it would break every
existing session/agent.

### Package notes

- `model` — `Vault`/`Item` plus `Find`/`Remove`. Pure data; no I/O.
- `crypto` — `DeriveKey`/`NewSalt` (Argon2id) and `Encrypt`/`Decrypt` (AES-GCM
  on raw bytes, so no layer shares a serialization format). `ErrWrongPassword`
  is returned on GCM auth failure.
- `storage` — the `VaultFile` envelope (`New`/`Decode`), atomic `0600` `Save`,
  `Load`, and **all path handling** (`Dir`/`Path`/`SocketPath`).
- `agent` — server (`Run`, `agent.handle`), client (`Alive`/`Lock`/`Status`/
  `Encrypt`/`Decrypt`), `Spawn`, and build-tagged `detachSysProcAttr`
  (`detach_unix.go`/`detach_windows.go` — the only platform-specific code).
  `IsAgentInvocation` lets cli route the hidden `__agent` command here.
- `cli` — one `cmdX` per subcommand plus `openVault`/`saveVault`, prompts, and
  `Execute(args)` (dispatch + usage + exit code). `prompt.go`: `readSecret`
  reads without echo via `golang.org/x/term`, falling back to a plain read when
  stdin is not a TTY (makes piped/scripted input and tests work). **All stdin
  reads share the single package-level `stdin` buffered reader** — do not create
  new `bufio.Reader`s on `os.Stdin`, or buffered bytes past the first line get
  silently dropped between prompts. Misuse returns `*usageErr` (via
  `usageError`), which `Execute` detects with `errors.As` to print usage.
- `cmd/lockbox` — just `os.Exit(cli.Execute(os.Args[1:]))`.

## Conventions / gotchas

- Dependencies are intentionally minimal: stdlib plus `golang.org/x/crypto`
  (Argon2id) and `golang.org/x/term` (no-echo input). Keep it that way.
- Crypto parameters live in `crypto`; the file `version` is `storage.FileVersion`.
  Any incompatible format/KDF change must bump `FileVersion` and handle the old
  version in `storage.VaultFile.Decode`.
- `cmdInit` refuses to overwrite an existing vault; `cmdAdd` rejects duplicate
  services. Preserve these guards — there is no undo and no password recovery.
- Unix-socket paths are limited (~104 chars on macOS). The default home-based
  path is fine; tests that set a long `$HOME` will fail to bind the socket. Use a
  short `$HOME` (e.g. `/tmp/lbh`) when running the binary end-to-end in tests.
- The 24h expiry can't be waited out in tests; `agent/agent_test.go` exercises
  `agent.handle` directly over `net.Pipe` with a past `expiresAt`.

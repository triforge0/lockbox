# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
go build -o lockbox .                 # build the CLI binary
go test ./...                         # run all tests
go test -run TestEncryptDecrypt ./... # run a single test by name
go vet ./...                          # static checks
GOOS=windows GOARCH=amd64 go build -o lockbox.exe .   # cross-compile
```

There is no separate lint config; `go vet` plus `gofmt` are the bar.

## Architecture

`lockbox` is a single-package (`package main`) CLI password manager. The whole
data store is one AES-256-GCM-encrypted blob at `~/.lockbox/store.vault`; there
is no database, no network, and no per-item encryption.

The flow for every mutating command is the same three steps — **decrypt the
whole vault → modify the in-memory `Vault` → re-encrypt and atomically save**.
Understanding that loop is the key to the codebase:

- `vault.go` — the security and persistence core. Holds the data model
  (`Vault`/`Item`), the on-disk envelope (`vaultFile` with version/salt/nonce/
  ciphertext), and the crypto: `deriveKey` (Argon2id), `encryptVault`,
  `decryptVault`, plus `loadVaultFile`/`saveVaultFile`. Invariant: plaintext is
  never written to disk, and **a new salt and nonce are generated on every
  save** (so `encryptVault` always produces fresh ciphertext). Saves are atomic
  (temp file + `os.Rename`) and `0600`.
- `commands.go` — one `cmdX` function per subcommand. The shared helpers
  `openVault` (load → prompt password → decrypt, returning the password so it
  can reseal) and `resealVault` (encrypt → save) encode the decrypt/modify/
  encrypt loop. Add the same pair of helpers when introducing new mutating
  commands rather than re-implementing the cycle.
- `prompt.go` — terminal input. `readSecret` reads the master password without
  echo via `golang.org/x/term`, and falls back to a plain line read when stdin
  is not a TTY (this is what makes piped/scripted input and tests work). **All
  stdin reads share the single package-level `stdin` buffered reader** — do not
  create new `bufio.Reader`s on `os.Stdin`, or buffered bytes past the first
  line get silently dropped between prompts.
- `main.go` — arg dispatch and usage. Misuse is signaled by returning a
  `*usageErr` (via `usageError(...)`), which `main` detects with `errors.As` to
  print usage; any other error prints just the message. Exit code is 1 on error.

## Conventions / gotchas

- Dependencies are intentionally minimal: stdlib plus `golang.org/x/crypto`
  (Argon2id) and `golang.org/x/term` (no-echo input). Keep it that way.
- Crypto parameters and the file `version` are constants in `vault.go`. Any
  incompatible change to the format or KDF params must bump `vaultFileVersion`
  and handle the old version in `decryptVault`.
- `cmdInit` refuses to overwrite an existing vault; `cmdAdd` rejects duplicate
  services. Preserve these guards — there is no undo and no password recovery.

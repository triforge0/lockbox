# lockbox

A minimal, secure, cross-platform CLI password manager written in Go.

Credentials are stored in a single encrypted file at `~/.lockbox/store.vault`.
There is no database and no network access — just one local, encrypted blob.

## Security

- The encryption key is derived from your master password with **Argon2id**
  (64 MiB, 1 pass, 4 lanes).
- The vault is encrypted as a single blob with **AES-256-GCM**.
- Plaintext is never written to disk. A fresh salt and nonce are generated on
  every save.
- The master password is read without echoing to the terminal, and the vault
  file is written with `0600` permissions.

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
lockbox add <service>       # add credentials (prompts for username + password)
lockbox get <service>       # print credentials for a service
lockbox list                # list all stored service names
lockbox delete <service>    # remove a service
```

Every command except `init` prompts for the master password. There is no
recovery if you forget it — by design.

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

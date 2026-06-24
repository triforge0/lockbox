// Command lockbox is a minimal, cross-platform CLI password manager.
//
// Credentials live in a single AES-256-GCM encrypted vault at
// ~/.lockbox/store.vault. The encryption key is derived from a master password
// using Argon2id and, after "unlock", held in memory by a background agent for
// 24 hours. Plaintext is never written to disk.
//
// All behavior lives in internal packages; this is just the entry point.
package main

import (
	"os"

	"lockbox/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:]))
}

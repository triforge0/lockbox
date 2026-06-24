// Command lockbox is a minimal, cross-platform CLI password manager.
//
// Credentials live in a single AES-256-GCM encrypted vault at
// ~/.lockbox/store.vault. The encryption key is derived from a master
// password using Argon2id. Plaintext is never written to disk.
package main

import (
	"errors"
	"fmt"
	"os"
)

// usageErr marks an error as a misuse of the CLI so main can print usage.
type usageErr struct{ msg string }

func (e *usageErr) Error() string { return e.msg }

func usageError(msg string) error { return &usageErr{msg: msg} }

const usage = `lockbox - a simple, secure CLI password manager

Usage:
  lockbox <command> [arguments]

Commands:
  init                Create a new encrypted vault
  add <service>       Add credentials for a service
  get <service>       Show credentials for a service
  list                List all stored services
  delete <service>    Remove credentials for a service

The vault is stored at ~/.lockbox/store.vault and is encrypted with a master
password using Argon2id key derivation and AES-256-GCM.`

func main() {
	if err := run(os.Args[1:]); err != nil {
		var ue *usageErr
		if errors.As(err, &ue) {
			fmt.Fprintf(os.Stderr, "lockbox: %s\n\n%s\n", ue.msg, usage)
		} else {
			fmt.Fprintf(os.Stderr, "lockbox: %s\n", err)
		}
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Println(usage)
		return nil
	}

	command, rest := args[0], args[1:]
	switch command {
	case "init":
		return cmdInit(rest)
	case "add":
		return cmdAdd(rest)
	case "get":
		return cmdGet(rest)
	case "list":
		return cmdList(rest)
	case "delete":
		return cmdDelete(rest)
	case "help", "-h", "--help":
		fmt.Println(usage)
		return nil
	default:
		return usageError(fmt.Sprintf("unknown command %q", command))
	}
}

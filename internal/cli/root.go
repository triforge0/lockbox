// Package cli is the command-line layer: argument dispatch, user prompts, and
// output formatting. It wires together the model, crypto, storage, and agent
// packages but contains no business or crypto logic of its own.
package cli

import (
	"errors"
	"fmt"
	"os"

	"lockbox/internal/agent"
)

// usageErr marks an error as a misuse of the CLI so Execute can print usage.
type usageErr struct{ msg string }

func (e *usageErr) Error() string { return e.msg }

func usageError(msg string) error { return &usageErr{msg: msg} }

const usage = `lockbox - a simple, secure CLI password manager

Usage:
  lockbox <command> [arguments]

Commands:
  init                Create a new encrypted vault
  unlock              Start a 24h session (prompts for the master password)
  add <service>       Add credentials for a service
  get <service>       Show credentials for a service
  list                List all stored services
  delete <service>    Remove credentials for a service
  lock                End the session immediately

The vault is stored at ~/.lockbox/store.vault and is encrypted with a master
password using Argon2id key derivation and AES-256-GCM. After "unlock", a
background agent holds the key in memory for 24 hours so other commands don't
re-prompt; "lock" clears it.`

// Execute runs the CLI with the given arguments (typically os.Args[1:]) and
// returns a process exit code. All user-facing output, including usage on
// misuse, is handled here.
func Execute(args []string) int {
	if err := run(args); err != nil {
		var ue *usageErr
		if errors.As(err, &ue) {
			fmt.Fprintf(os.Stderr, "lockbox: %s\n\n%s\n", ue.msg, usage)
		} else {
			fmt.Fprintf(os.Stderr, "lockbox: %s\n", err)
		}
		return 1
	}
	return 0
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Println(usage)
		return nil
	}

	command, rest := args[0], args[1:]

	// Hidden: the detached background session process. Not for direct use.
	if agent.IsAgentInvocation(command) {
		return agent.Run()
	}

	switch command {
	case "init":
		return cmdInit(rest)
	case "unlock":
		return cmdUnlock(rest)
	case "lock":
		return cmdLock(rest)
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

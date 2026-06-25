package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"lockbox/internal/agent"
	"lockbox/internal/crypto"
	"lockbox/internal/model"
	"lockbox/internal/storage"
)

// sessionError rewrites agent.ErrNoSession into a message naming the right
// unlock command for this vault (the agent's generic text can't know --vault).
func sessionError(name string, err error) error {
	if errors.Is(err, agent.ErrNoSession) {
		return fmt.Errorf("locked: run %s first", unlockHint(name))
	}
	return err
}

// unlockHint returns the command the user should run to unlock the given vault,
// spelling out --vault for non-default vaults.
func unlockHint(name string) string {
	if name == storage.DefaultVault {
		return `"lockbox unlock"`
	}
	return fmt.Sprintf("\"lockbox --vault %s unlock\"", name)
}

// cmdInit creates a new, empty encrypted vault. It refuses to overwrite an
// existing vault so a stored set of credentials can't be wiped by accident.
// init does not start a session; run "lockbox unlock" afterwards.
func cmdInit(name string, args []string) error {
	if len(args) != 0 {
		return usageError("init takes no arguments")
	}

	exists, err := storage.Exists(name)
	if err != nil {
		return err
	}
	if exists {
		path, _ := storage.Path(name)
		return fmt.Errorf("a vault already exists at %s", path)
	}

	password, err := readNewMasterPassword()
	if err != nil {
		return err
	}

	salt, err := crypto.NewSalt()
	if err != nil {
		return err
	}
	key := crypto.DeriveKey(password, salt, crypto.Argon2Time)

	plaintext, err := json.Marshal(&model.Vault{Items: []model.Item{}})
	if err != nil {
		return fmt.Errorf("marshal vault: %w", err)
	}
	nonce, ciphertext, err := crypto.Encrypt(key, plaintext)
	if err != nil {
		return err
	}
	if err := storage.Save(name, storage.New(salt, nonce, ciphertext)); err != nil {
		return err
	}

	path, _ := storage.Path(name)
	fmt.Printf("Initialized empty vault %q at %s\n", name, path)
	fmt.Printf("Run %s to start a session.\n", unlockHint(name))
	return nil
}

// cmdUnlock prompts for the master password, verifies it against the vault, and
// starts a detached agent that holds the derived key in memory. The session
// auto-locks after agent.IdleTTL of inactivity (agent.MaxTTL absolute cap).
func cmdUnlock(name string, args []string) error {
	if len(args) != 0 {
		return usageError("unlock takes no arguments")
	}

	vf, err := storage.Load(name)
	if err != nil {
		return err
	}
	salt, nonce, ciphertext, err := vf.Decode()
	if err != nil {
		return err
	}

	password, err := readMasterPassword()
	if err != nil {
		return err
	}
	key := crypto.DeriveKey(password, salt, argonTimeForVersion(vf.Version))

	// Verify the password by actually decrypting before starting a session.
	plaintext, err := crypto.Decrypt(key, nonce, ciphertext)
	if err != nil {
		return err
	}

	// Transparently re-key an older vault to the current Argon2id parameters.
	// We have the password here, so we can re-derive against the (unchanged)
	// salt and re-encrypt; the agent only ever sees the upgraded key.
	if vf.Version < storage.FileVersion {
		key = crypto.DeriveKey(password, salt, crypto.Argon2Time)
		nonce, ciphertext, err = crypto.Encrypt(key, plaintext)
		if err != nil {
			return err
		}
		if err := storage.Save(name, storage.New(salt, nonce, ciphertext)); err != nil {
			return err
		}
	}

	// Replace any existing session so the idle clock restarts cleanly.
	if agent.Alive(name) {
		_ = agent.Lock(name)
		waitForAgentGone(name, time.Second)
	}

	if err := agent.Spawn(name, key, salt); err != nil {
		return err
	}

	expiresAt, err := agent.Status(name)
	if err != nil {
		return err
	}
	fmt.Printf("Vault %q unlocked. Auto-locks at %s if idle; each use extends it (%s max).\n",
		name, formatExpiry(expiresAt), agent.MaxTTL)
	return nil
}

// argonTimeForVersion maps an on-disk vault version to the Argon2id time cost it
// was written with, so an existing vault can be opened before being upgraded.
func argonTimeForVersion(version int) uint32 {
	if version <= 1 {
		return crypto.Argon2TimeV1
	}
	return crypto.Argon2Time
}

// cmdLock immediately clears the in-memory session for the named vault.
func cmdLock(name string, args []string) error {
	if len(args) != 0 {
		return usageError("lock takes no arguments")
	}
	if !agent.Alive(name) {
		fmt.Println("Already locked.")
		return nil
	}
	if err := agent.Lock(name); err != nil {
		return err
	}
	waitForAgentGone(name, time.Second)
	fmt.Printf("Locked. Run %s to use the vault again.\n", unlockHint(name))
	return nil
}

// cmdAdd adds a new credential. Requires an active session.
func cmdAdd(name string, args []string) error {
	if len(args) != 1 {
		return usageError("add requires exactly one <service> argument")
	}
	service := args[0]

	vault, err := openVault(name)
	if err != nil {
		return err
	}

	if vault.Find(service) != nil {
		return fmt.Errorf("service %q already exists; delete it first to replace", service)
	}

	username, err := readLine("Username: ")
	if err != nil {
		return err
	}
	itemPassword, err := readSecret("Password: ")
	if err != nil {
		return err
	}

	vault.Items = append(vault.Items, model.Item{
		Service:  service,
		Username: username,
		Password: itemPassword,
	})

	if err := saveVault(name, vault); err != nil {
		return err
	}

	fmt.Printf("Added credentials for %q\n", service)
	return nil
}

// cmdGet prints the credentials for a service. Requires an active session.
// With -p/--password it prints only the password, with no label or trailing
// newline, so it pipes cleanly (e.g. `lockbox get github -p | pbcopy`).
func cmdGet(name string, args []string) error {
	passwordOnly := false
	rest := args[:0:0]
	for _, a := range args {
		switch a {
		case "-p", "--password":
			passwordOnly = true
		default:
			rest = append(rest, a)
		}
	}
	if len(rest) != 1 {
		return usageError("get requires exactly one <service> argument")
	}
	service := rest[0]

	vault, err := openVault(name)
	if err != nil {
		return err
	}

	item := vault.Find(service)
	if item == nil {
		return fmt.Errorf("no credentials found for %q", service)
	}

	if passwordOnly {
		fmt.Print(item.Password)
		return nil
	}

	fmt.Printf("Service:  %s\n", item.Service)
	fmt.Printf("Username: %s\n", item.Username)
	fmt.Printf("Password: %s\n", item.Password)
	return nil
}

// cmdList prints all stored service names. Requires an active session.
func cmdList(name string, args []string) error {
	if len(args) != 0 {
		return usageError("list takes no arguments")
	}

	vault, err := openVault(name)
	if err != nil {
		return err
	}

	if len(vault.Items) == 0 {
		fmt.Println("Vault is empty.")
		return nil
	}

	services := make([]string, 0, len(vault.Items))
	for _, item := range vault.Items {
		services = append(services, item.Service)
	}
	sort.Strings(services)

	for _, s := range services {
		fmt.Println(s)
	}
	return nil
}

// cmdDelete removes a service. Requires an active session. Because there is no
// undo, it asks for confirmation first; -f/--force skips the prompt.
func cmdDelete(name string, args []string) error {
	force := false
	rest := args[:0:0]
	for _, a := range args {
		switch a {
		case "-f", "--force":
			force = true
		default:
			rest = append(rest, a)
		}
	}
	if len(rest) != 1 {
		return usageError("delete requires exactly one <service> argument")
	}
	service := rest[0]

	vault, err := openVault(name)
	if err != nil {
		return err
	}

	if vault.Find(service) == nil {
		return fmt.Errorf("no credentials found for %q", service)
	}

	if !force {
		answer, err := readLine(fmt.Sprintf("Delete credentials for %q? This cannot be undone [y/N]: ", service))
		if err != nil {
			return err
		}
		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "y", "yes":
		default:
			fmt.Println("Aborted.")
			return nil
		}
	}

	vault.Remove(service)
	if err := saveVault(name, vault); err != nil {
		return err
	}

	fmt.Printf("Deleted credentials for %q\n", service)
	return nil
}

// cmdStatus reports whether the selected vault has a live session and, if so,
// when it will auto-lock. Requires no session of its own.
func cmdStatus(name string, args []string) error {
	if len(args) != 0 {
		return usageError("status takes no arguments")
	}
	if !agent.Alive(name) {
		fmt.Printf("Vault %q is locked. Run %s to start a session.\n", name, unlockHint(name))
		return nil
	}
	expiresAt, err := agent.Status(name)
	if err != nil {
		return sessionError(name, err)
	}
	fmt.Printf("Vault %q is unlocked. Auto-locks at %s if idle (%s max).\n",
		name, formatExpiry(expiresAt), agent.MaxTTL)
	return nil
}

// cmdGen prints a freshly generated random password. An optional argument sets
// the length (default genDefaultLength). It needs no vault or session.
func cmdGen(args []string) error {
	length := genDefaultLength
	if len(args) > 1 {
		return usageError("gen takes at most one <length> argument")
	}
	if len(args) == 1 {
		n, err := strconv.Atoi(args[0])
		if err != nil {
			return usageError(fmt.Sprintf("invalid length %q", args[0]))
		}
		length = n
	}
	pw, err := crypto.GeneratePassword(length)
	if err != nil {
		return err
	}
	fmt.Println(pw)
	return nil
}

// genDefaultLength is the password length used by `gen` when none is given.
const genDefaultLength = 20

// cmdVaults lists every vault in ~/.lockbox and whether each is unlocked.
func cmdVaults(args []string) error {
	if len(args) != 0 {
		return usageError("vaults takes no arguments")
	}
	names, err := storage.ListVaults()
	if err != nil {
		return err
	}
	if len(names) == 0 {
		fmt.Println("No vaults yet. Run \"lockbox init\" to create one.")
		return nil
	}
	for _, n := range names {
		status := "locked"
		if agent.Alive(n) {
			status = "unlocked"
		}
		fmt.Printf("%-20s %s\n", n, status)
	}
	return nil
}

// openVault loads the named vault's file and decrypts it through its running
// agent. It never prompts for a password; if there is no session it returns
// agent.ErrNoSession.
func openVault(name string) (*model.Vault, error) {
	vf, err := storage.Load(name)
	if err != nil {
		return nil, err
	}
	_, nonce, ciphertext, err := vf.Decode()
	if err != nil {
		return nil, err
	}
	plaintext, err := agent.Decrypt(name, nonce, ciphertext)
	if err != nil {
		return nil, sessionError(name, err)
	}
	var v model.Vault
	if err := json.Unmarshal(plaintext, &v); err != nil {
		return nil, fmt.Errorf("parse decrypted vault: %w", err)
	}
	return &v, nil
}

// saveVault encrypts the vault through the named agent and writes it to disk.
func saveVault(name string, vault *model.Vault) error {
	plaintext, err := json.Marshal(vault)
	if err != nil {
		return fmt.Errorf("marshal vault: %w", err)
	}
	salt, nonce, ciphertext, err := agent.Encrypt(name, plaintext)
	if err != nil {
		return sessionError(name, err)
	}
	return storage.Save(name, storage.New(salt, nonce, ciphertext))
}

// waitForAgentGone blocks until the named agent stops responding or the timeout
// elapses, so unlock/lock don't race the previous agent's shutdown.
func waitForAgentGone(name string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !agent.Alive(name) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// formatExpiry renders an RFC3339 timestamp in the local timezone, falling back
// to the raw value if it can't be parsed.
func formatExpiry(rfc3339 string) string {
	t, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		return rfc3339
	}
	return t.Local().Format("2006-01-02 15:04:05 MST")
}

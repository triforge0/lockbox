package cli

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"lockbox/internal/agent"
	"lockbox/internal/crypto"
	"lockbox/internal/model"
	"lockbox/internal/storage"
)

// cmdInit creates a new, empty encrypted vault. It refuses to overwrite an
// existing vault so a stored set of credentials can't be wiped by accident.
// init does not start a session; run "lockbox unlock" afterwards.
func cmdInit(args []string) error {
	if len(args) != 0 {
		return usageError("init takes no arguments")
	}

	exists, err := storage.Exists()
	if err != nil {
		return err
	}
	if exists {
		path, _ := storage.Path()
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
	if err := storage.Save(storage.New(salt, nonce, ciphertext)); err != nil {
		return err
	}

	path, _ := storage.Path()
	fmt.Printf("Initialized empty vault at %s\n", path)
	fmt.Println("Run \"lockbox unlock\" to start a session.")
	return nil
}

// cmdUnlock prompts for the master password, verifies it against the vault, and
// starts a detached agent that holds the derived key in memory. The session
// auto-locks after agent.IdleTTL of inactivity (agent.MaxTTL absolute cap).
func cmdUnlock(args []string) error {
	if len(args) != 0 {
		return usageError("unlock takes no arguments")
	}

	vf, err := storage.Load()
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
		if err := storage.Save(storage.New(salt, nonce, ciphertext)); err != nil {
			return err
		}
	}

	// Replace any existing session so the idle clock restarts cleanly.
	if agent.Alive() {
		_ = agent.Lock()
		waitForAgentGone(time.Second)
	}

	if err := agent.Spawn(key, salt); err != nil {
		return err
	}

	expiresAt, err := agent.Status()
	if err != nil {
		return err
	}
	fmt.Printf("Vault unlocked. Auto-locks at %s if idle; each use extends it (%s max).\n",
		formatExpiry(expiresAt), agent.MaxTTL)
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

// cmdLock immediately clears the in-memory session.
func cmdLock(args []string) error {
	if len(args) != 0 {
		return usageError("lock takes no arguments")
	}
	if !agent.Alive() {
		fmt.Println("Already locked.")
		return nil
	}
	if err := agent.Lock(); err != nil {
		return err
	}
	waitForAgentGone(time.Second)
	fmt.Println("Locked. Run \"lockbox unlock\" to use the vault again.")
	return nil
}

// cmdAdd adds a new credential. Requires an active session.
func cmdAdd(args []string) error {
	if len(args) != 1 {
		return usageError("add requires exactly one <service> argument")
	}
	service := args[0]

	vault, err := openVault()
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

	if err := saveVault(vault); err != nil {
		return err
	}

	fmt.Printf("Added credentials for %q\n", service)
	return nil
}

// cmdGet prints the credentials for a service. Requires an active session.
func cmdGet(args []string) error {
	if len(args) != 1 {
		return usageError("get requires exactly one <service> argument")
	}
	service := args[0]

	vault, err := openVault()
	if err != nil {
		return err
	}

	item := vault.Find(service)
	if item == nil {
		return fmt.Errorf("no credentials found for %q", service)
	}

	fmt.Printf("Service:  %s\n", item.Service)
	fmt.Printf("Username: %s\n", item.Username)
	fmt.Printf("Password: %s\n", item.Password)
	return nil
}

// cmdList prints all stored service names. Requires an active session.
func cmdList(args []string) error {
	if len(args) != 0 {
		return usageError("list takes no arguments")
	}

	vault, err := openVault()
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

// cmdDelete removes a service. Requires an active session.
func cmdDelete(args []string) error {
	if len(args) != 1 {
		return usageError("delete requires exactly one <service> argument")
	}
	service := args[0]

	vault, err := openVault()
	if err != nil {
		return err
	}

	if !vault.Remove(service) {
		return fmt.Errorf("no credentials found for %q", service)
	}

	if err := saveVault(vault); err != nil {
		return err
	}

	fmt.Printf("Deleted credentials for %q\n", service)
	return nil
}

// openVault loads the on-disk file and decrypts it through the running agent. It
// never prompts for a password; if there is no session it returns
// agent.ErrNoSession.
func openVault() (*model.Vault, error) {
	vf, err := storage.Load()
	if err != nil {
		return nil, err
	}
	_, nonce, ciphertext, err := vf.Decode()
	if err != nil {
		return nil, err
	}
	plaintext, err := agent.Decrypt(nonce, ciphertext)
	if err != nil {
		return nil, err
	}
	var v model.Vault
	if err := json.Unmarshal(plaintext, &v); err != nil {
		return nil, fmt.Errorf("parse decrypted vault: %w", err)
	}
	return &v, nil
}

// saveVault encrypts the vault through the agent and writes it to disk.
func saveVault(vault *model.Vault) error {
	plaintext, err := json.Marshal(vault)
	if err != nil {
		return fmt.Errorf("marshal vault: %w", err)
	}
	salt, nonce, ciphertext, err := agent.Encrypt(plaintext)
	if err != nil {
		return err
	}
	return storage.Save(storage.New(salt, nonce, ciphertext))
}

// waitForAgentGone blocks until the agent stops responding or the timeout
// elapses, so unlock/lock don't race the previous agent's shutdown.
func waitForAgentGone(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !agent.Alive() {
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

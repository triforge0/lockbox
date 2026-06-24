package main

import (
	"fmt"
	"sort"
)

// cmdInit creates a new, empty encrypted vault. It refuses to overwrite an
// existing vault so a stored set of credentials can't be wiped by accident.
func cmdInit(args []string) error {
	if len(args) != 0 {
		return usageError("init takes no arguments")
	}

	exists, err := vaultExists()
	if err != nil {
		return err
	}
	if exists {
		path, _ := vaultPath()
		return fmt.Errorf("a vault already exists at %s", path)
	}

	password, err := readNewMasterPassword()
	if err != nil {
		return err
	}

	vf, err := encryptVault(&Vault{Items: []Item{}}, password)
	if err != nil {
		return err
	}
	if err := saveVaultFile(vf); err != nil {
		return err
	}

	path, _ := vaultPath()
	fmt.Printf("Initialized empty vault at %s\n", path)
	return nil
}

// cmdAdd decrypts the vault, adds a new credential, and re-encrypts it.
func cmdAdd(args []string) error {
	if len(args) != 1 {
		return usageError("add requires exactly one <service> argument")
	}
	service := args[0]

	vault, password, err := openVault()
	if err != nil {
		return err
	}

	if vault.find(service) != nil {
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

	vault.Items = append(vault.Items, Item{
		Service:  service,
		Username: username,
		Password: itemPassword,
	})

	if err := resealVault(vault, password); err != nil {
		return err
	}

	fmt.Printf("Added credentials for %q\n", service)
	return nil
}

// cmdGet decrypts the vault and prints the credentials for a service.
func cmdGet(args []string) error {
	if len(args) != 1 {
		return usageError("get requires exactly one <service> argument")
	}
	service := args[0]

	vault, _, err := openVault()
	if err != nil {
		return err
	}

	item := vault.find(service)
	if item == nil {
		return fmt.Errorf("no credentials found for %q", service)
	}

	fmt.Printf("Service:  %s\n", item.Service)
	fmt.Printf("Username: %s\n", item.Username)
	fmt.Printf("Password: %s\n", item.Password)
	return nil
}

// cmdList decrypts the vault and prints all stored service names.
func cmdList(args []string) error {
	if len(args) != 0 {
		return usageError("list takes no arguments")
	}

	vault, _, err := openVault()
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

// cmdDelete decrypts the vault, removes a service, and re-encrypts it.
func cmdDelete(args []string) error {
	if len(args) != 1 {
		return usageError("delete requires exactly one <service> argument")
	}
	service := args[0]

	vault, password, err := openVault()
	if err != nil {
		return err
	}

	if !vault.remove(service) {
		return fmt.Errorf("no credentials found for %q", service)
	}

	if err := resealVault(vault, password); err != nil {
		return err
	}

	fmt.Printf("Deleted credentials for %q\n", service)
	return nil
}

// openVault loads the on-disk file, prompts for the master password, and
// returns the decrypted vault along with the password (needed to reseal it).
func openVault() (*Vault, string, error) {
	vf, err := loadVaultFile()
	if err != nil {
		return nil, "", err
	}
	password, err := readMasterPassword()
	if err != nil {
		return nil, "", err
	}
	vault, err := decryptVault(vf, password)
	if err != nil {
		return nil, "", err
	}
	return vault, password, nil
}

// resealVault re-encrypts and saves the vault with a fresh salt and nonce.
func resealVault(vault *Vault, password string) error {
	vf, err := encryptVault(vault, password)
	if err != nil {
		return err
	}
	return saveVaultFile(vf)
}

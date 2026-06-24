// Package model holds the decrypted, in-memory representation of the vault.
// It has no dependencies on storage, crypto, or the CLI.
package model

// Item is a single stored credential.
type Item struct {
	Service  string `json:"service"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Vault is the decrypted store: a flat list of credentials.
type Vault struct {
	Items []Item `json:"items"`
}

// Find returns a pointer to the item matching service, or nil if not present.
func (v *Vault) Find(service string) *Item {
	for i := range v.Items {
		if v.Items[i].Service == service {
			return &v.Items[i]
		}
	}
	return nil
}

// Remove deletes the item for service and reports whether anything was removed.
func (v *Vault) Remove(service string) bool {
	for i := range v.Items {
		if v.Items[i].Service == service {
			v.Items = append(v.Items[:i], v.Items[i+1:]...)
			return true
		}
	}
	return false
}

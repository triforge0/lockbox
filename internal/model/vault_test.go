package model

import "testing"

func TestVaultFindAndRemove(t *testing.T) {
	v := &Vault{Items: []Item{
		{Service: "a"}, {Service: "b"}, {Service: "c"},
	}}
	if v.Find("b") == nil {
		t.Error("Find(b) returned nil")
	}
	if v.Find("missing") != nil {
		t.Error("Find(missing) should be nil")
	}
	if !v.Remove("b") {
		t.Error("Remove(b) returned false")
	}
	if v.Find("b") != nil {
		t.Error("b still present after remove")
	}
	if v.Remove("b") {
		t.Error("Remove(b) twice returned true")
	}
	if len(v.Items) != 2 {
		t.Errorf("len = %d, want 2", len(v.Items))
	}
}

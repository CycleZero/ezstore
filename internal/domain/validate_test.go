package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateName(t *testing.T) {
	valid := []string{"a", "a/b", "team/stripe-key", "team/stripe_key.v2", "A1/b2"}
	for _, name := range valid {
		if err := ValidateName(name); err != nil {
			t.Errorf("ValidateName(%q) = %v, want nil", name, err)
		}
	}

	invalid := []string{
		"", "/a", "a/", "a//b", "a/../b", "a/./b",
		"a b", "a*b", "a?b", "team/", strings.Repeat("x", 200),
	}
	for _, name := range invalid {
		if err := ValidateName(name); err == nil {
			t.Errorf("ValidateName(%q) = nil, want error", name)
		} else if !errors.Is(err, ErrInvalidName) {
			t.Errorf("ValidateName(%q) error type = %v, want ErrInvalidName", name, err)
		}
	}
}

func TestValidateValue(t *testing.T) {
	if err := ValidateValue([]byte("x")); err != nil {
		t.Errorf("small value rejected: %v", err)
	}
	if err := ValidateValue(nil); err == nil {
		t.Error("empty value must be rejected")
	}
	big := make([]byte, MaxValueBytes+1)
	if err := ValidateValue(big); !errors.Is(err, ErrValueTooLarge) {
		t.Errorf("oversized value error = %v, want ErrValueTooLarge", err)
	}
}

func TestParsePermsAndScopes(t *testing.T) {
	perms, err := ParsePerms([]string{"Read", "write", "read"})
	if err != nil {
		t.Fatalf("ParsePerms: %v", err)
	}
	if len(perms) != 2 || perms[0] != "read" || perms[1] != "write" {
		t.Errorf("ParsePerms = %v, want [read write]", perms)
	}
	if _, err := ParsePerms([]string{"root"}); err == nil {
		t.Error("unknown permission must be rejected")
	}

	scopes, err := ParseScopes([]string{"team/**", "/shared/*/"})
	if err != nil {
		t.Fatalf("ParseScopes: %v", err)
	}
	if len(scopes) != 2 || scopes[0] != "shared/*" || scopes[1] != "team/**" {
		t.Errorf("ParseScopes = %v", scopes)
	}
	if _, err := ParseScopes([]string{"a//b"}); err == nil {
		t.Error("empty scope segment must be rejected")
	}
}

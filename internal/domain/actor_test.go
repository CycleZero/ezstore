package domain

import "testing"

func TestMatchScope(t *testing.T) {
	cases := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"**", "team/stripe/key", true},
		{"*", "team", true},
		{"*", "team/stripe", false},
		{"team/*", "team/stripe", true},
		{"team/*", "team/stripe/key", false},
		{"team/**", "team/stripe/key", true},
		{"team/**", "team", true},
		{"team/**", "other/team", false},
		{"team/stripe/key", "team/stripe/key", true},
		{"team/stripe/key", "team/stripe", false},
		{"team/*/key", "team/stripe/key", true},
		{"team/*/key", "team/other/key", true},
		{"team/*/key", "team/other/other", false},
		{"a/**/z", "a/z", true},
		{"a/**/z", "a/b/c/z", true},
		{"a/**/z", "a/b/c", false},
		{"**/key", "a/b/key", true},
		{"**/key", "key", true},
	}
	for _, tc := range cases {
		if got := MatchScope(tc.pattern, tc.name); got != tc.want {
			t.Errorf("MatchScope(%q, %q) = %v, want %v", tc.pattern, tc.name, got, tc.want)
		}
	}
}

func TestActorCan(t *testing.T) {
	actor := Actor{
		Scopes: []string{"team/**"},
		Perms:  []string{string(PermRead), string(PermWrite)},
	}
	if !actor.Can(PermRead, "team/a") {
		t.Error("expected read on team/a")
	}
	if !actor.Can(PermWrite, "team/a/b") {
		t.Error("expected write on team/a/b")
	}
	if actor.Can(PermDelete, "team/a") {
		t.Error("delete was not granted")
	}
	if actor.Can(PermRead, "other/a") {
		t.Error("scope must not cover other/a")
	}
	if actor.CanAdmin() {
		t.Error("admin was not granted")
	}
}

func TestZeroActorHasNoRights(t *testing.T) {
	var actor Actor
	if actor.Can(PermRead, "anything") {
		t.Error("zero actor must have no permissions")
	}
	if actor.CanAdmin() {
		t.Error("zero actor must not be admin")
	}
}

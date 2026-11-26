package domain

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// Perm is a coarse capability granted to a token.
type Perm string

// Permission set. A token carries any combination of these.
const (
	PermRead   Perm = "read"   // get, list, history
	PermWrite  Perm = "write"  // put, rollback
	PermDelete Perm = "delete" // delete, purge
	PermAdmin  Perm = "admin"  // token management
)

var allPerms = []Perm{PermRead, PermWrite, PermDelete, PermAdmin}

// ParsePerms validates and normalises a permission list.
func ParsePerms(in []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		p := strings.ToLower(strings.TrimSpace(raw))
		if p == "" {
			continue
		}
		valid := false
		for _, known := range allPerms {
			if p == string(known) {
				valid = true
				break
			}
		}
		if !valid {
			return nil, fmt.Errorf("%w: unknown permission %q", ErrInvalidArgument, raw)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: at least one permission is required", ErrInvalidArgument)
	}
	sort.Strings(out)
	return out, nil
}

// ParseScopes validates and normalises scope globs.
func ParseScopes(in []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		s = strings.TrimPrefix(s, "/")
		s = strings.TrimSuffix(s, "/")
		if s == "" {
			return nil, fmt.Errorf("%w: empty scope", ErrInvalidArgument)
		}
		if strings.Contains(s, "//") {
			return nil, fmt.Errorf("%w: scope %q contains an empty segment", ErrInvalidArgument, raw)
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: at least one scope is required", ErrInvalidArgument)
	}
	sort.Strings(out)
	return out, nil
}

// Actor is the authenticated caller. The zero value is an unknown caller with
// no rights at all, which is the safe default.
type Actor struct {
	ID     string
	Name   string
	Scopes []string
	Perms  []string
}

// SystemActor is used by local CLI commands, which already hold the master key
// file and therefore have full authority over the database.
func SystemActor() Actor {
	return Actor{
		ID:     "system",
		Name:   "local-cli",
		Scopes: []string{"**"},
		Perms:  []string{string(PermRead), string(PermWrite), string(PermDelete), string(PermAdmin)},
	}
}

// Has reports whether the actor holds perm on any scope.
func (a Actor) Has(perm Perm) bool {
	for _, p := range a.Perms {
		if p == string(perm) {
			return true
		}
	}
	return false
}

// Can reports whether the actor may perform perm on the named secret.
func (a Actor) Can(perm Perm, name string) bool {
	if !a.Has(perm) {
		return false
	}
	for _, scope := range a.Scopes {
		if MatchScope(scope, name) {
			return true
		}
	}
	return false
}

// CanAdmin reports whether the actor may manage tokens.
func (a Actor) CanAdmin() bool { return a.Has(PermAdmin) }

// MatchScope reports whether a secret name falls under a scope glob.
//
// Grammar:
//
//	"*"       matches one segment           e.g. "team/*" matches "team/a"
//	"**"      matches zero or more segments e.g. "team/**" matches "team/a/b"
//	literal   matches exactly               e.g. "team/a"
func MatchScope(pattern, name string) bool {
	return matchSegments(splitScope(pattern), splitScope(name))
}

func splitScope(s string) []string {
	s = strings.Trim(s, "/")
	if s == "" {
		return nil
	}
	return strings.Split(s, "/")
}

func matchSegments(pat, seg []string) bool {
	for {
		if len(pat) == 0 {
			return len(seg) == 0
		}
		if pat[0] == "**" {
			// Collapse consecutive "**" so the recursion stays linear.
			rest := pat
			for len(rest) > 0 && rest[0] == "**" {
				rest = rest[1:]
			}
			if len(rest) == 0 {
				return true
			}
			for i := 0; i <= len(seg); i++ {
				if matchSegments(rest, seg[i:]) {
					return true
				}
			}
			return false
		}
		if len(seg) == 0 {
			return false
		}
		if ok, err := path.Match(pat[0], seg[0]); err != nil || !ok {
			return false
		}
		pat, seg = pat[1:], seg[1:]
	}
}

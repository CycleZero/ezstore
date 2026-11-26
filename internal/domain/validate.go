package domain

import (
	"fmt"
	"regexp"
	"strings"
)

var segmentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ValidateName checks a secret name. Names are slash-separated segments so that
// scope globs stay meaningful; wildcard characters are rejected so a stored
// name can never be confused with a pattern.
func ValidateName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: name is empty", ErrInvalidName)
	}
	if len(name) > MaxNameBytes {
		return fmt.Errorf("%w: name exceeds %d bytes", ErrInvalidName, MaxNameBytes)
	}
	if strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") {
		return fmt.Errorf("%w: %q has a leading or trailing slash", ErrInvalidName, name)
	}
	if strings.Contains(name, "//") {
		return fmt.Errorf("%w: %q has an empty segment", ErrInvalidName, name)
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("%w: %q contains a relative segment", ErrInvalidName, name)
		}
		if !segmentPattern.MatchString(seg) {
			return fmt.Errorf("%w: segment %q must match [A-Za-z0-9][A-Za-z0-9._-]*", ErrInvalidName, seg)
		}
	}
	return nil
}

// ValidatePrefix checks a listing prefix. Unlike a name it may be empty and may
// end with a slash.
func ValidatePrefix(prefix string) error {
	if prefix == "" {
		return nil
	}
	prefix = strings.TrimSuffix(prefix, "/")
	if prefix == "" {
		return fmt.Errorf("%w: prefix is empty", ErrInvalidName)
	}
	return ValidateName(prefix)
}

// ValidateValue enforces the value size cap.
func ValidateValue(value []byte) error {
	if len(value) == 0 {
		return fmt.Errorf("%w: value is empty", ErrInvalidArgument)
	}
	if len(value) > MaxValueBytes {
		return fmt.Errorf("%w: value is %d bytes, limit is %d", ErrValueTooLarge, len(value), MaxValueBytes)
	}
	return nil
}

// ValidateTokenName applies the same segment rules to token names so both live
// in one namespace-free but predictable format.
func ValidateTokenName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: token name is empty", ErrInvalidArgument)
	}
	if len(name) > MaxNameBytes {
		return fmt.Errorf("%w: token name exceeds %d bytes", ErrInvalidArgument, MaxNameBytes)
	}
	if !segmentPattern.MatchString(name) {
		return fmt.Errorf("%w: token name must match [A-Za-z0-9][A-Za-z0-9._-]*", ErrInvalidArgument)
	}
	return nil
}

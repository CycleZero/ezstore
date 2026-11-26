//go:build !windows

package keyring

import (
	"fmt"
	"os"
)

const isWindows = false

func protect(_ string, key []byte) ([]byte, error) {
	out := make([]byte, len(key))
	copy(out, key)
	return out, nil
}

func unprotect(path string, raw []byte) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("master key file %s has permissions %04o, want 0600", path, mode)
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	return out, nil
}

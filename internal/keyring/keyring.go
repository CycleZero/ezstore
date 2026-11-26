// Package keyring loads and stores the ezstore master key.
//
// On Windows the key file is wrapped with DPAPI in user scope, so another
// account on the same machine cannot unwrap it. Elsewhere the file is a raw
// 32-byte key guarded by 0600 permissions and an explicit mode check.
//
// EZSTORE_MASTER_KEY overrides the key file. That mode is convenient for
// containers and CI but is the weakest option: anything that can read the
// process environment can read the key.
package keyring

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"ezstore/internal/crypto"
)

// EnvMasterKey is the environment variable that overrides the key file.
const EnvMasterKey = "EZSTORE_MASTER_KEY"

// ErrMissing means no master key has been created yet.
var ErrMissing = errors.New("master key not found: run 'ezstore init' first")

// Load returns the master key stored at path.
func Load(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrMissing
		}
		return nil, err
	}
	key, err := unprotect(path, raw)
	if err != nil {
		return nil, fmt.Errorf("unwrap master key %s: %w", path, err)
	}
	if len(key) != crypto.KeySize {
		return nil, fmt.Errorf("master key %s has invalid length %d", path, len(key))
	}
	return key, nil
}

// Save writes the master key to path, wrapping it for the current platform.
func Save(path string, key []byte) error {
	if len(key) != crypto.KeySize {
		return fmt.Errorf("master key must be %d bytes", crypto.KeySize)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	wrapped, err := protect(path, key)
	if err != nil {
		return fmt.Errorf("wrap master key: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, wrapped, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil && !isWindows {
		return err
	}
	return os.Rename(tmp, path)
}

// Ensure loads the master key at path, creating one when neither the file nor
// the environment override exists. created reports whether a key was generated.
func Ensure(path string) (key []byte, created bool, err error) {
	if env := os.Getenv(EnvMasterKey); env != "" {
		k, perr := crypto.ParseKey(env)
		if perr != nil {
			return nil, false, fmt.Errorf("%s: %w", EnvMasterKey, perr)
		}
		return k, false, nil
	}
	key, err = Load(path)
	if err == nil {
		return key, false, nil
	}
	if !errors.Is(err, ErrMissing) {
		return nil, false, err
	}
	key, err = crypto.GenerateKey()
	if err != nil {
		return nil, false, err
	}
	if err := Save(path, key); err != nil {
		return nil, false, err
	}
	return key, true, nil
}

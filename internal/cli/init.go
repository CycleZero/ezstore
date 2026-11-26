package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"ezstore/internal/config"
	"ezstore/internal/domain"
	"ezstore/internal/keyring"
	"ezstore/internal/repository/gormstore"
)

func cmdInit(cfgPath string, args []string) int {
	flags := newFlagSet("init")
	driver := flags.String("driver", "", "database driver: sqlite or mysql")
	dsn := flags.String("dsn", "", "database DSN (sqlite file path or MySQL DSN)")
	adminToken := flags.Bool("admin-token", false, "create an admin token and print it")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	if _, err := os.Stat(cfgPath); errors.Is(err, os.ErrNotExist) {
		if err := config.WriteDefault(cfgPath); err != nil {
			return fail(err)
		}
		fmt.Printf("created config  %s\n", cfgPath)
	} else if err != nil {
		return fail(err)
	} else {
		fmt.Printf("config exists  %s\n", cfgPath)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fail(err)
	}
	if *driver != "" {
		cfg.Database.Driver = *driver
	}
	if *dsn != "" {
		cfg.Database.DSN = *dsn
	}
	if *driver != "" || *dsn != "" {
		if err := rewriteDatabase(cfgPath, cfg); err != nil {
			return fail(err)
		}
		fmt.Printf("updated config  driver=%s\n", cfg.Database.Driver)
	}

	_, created, err := keyring.Ensure(cfg.MasterKeyPath())
	if err != nil {
		return fail(err)
	}
	if created {
		fmt.Printf("created key     %s\n", cfg.MasterKeyPath())
	} else {
		fmt.Printf("key exists      %s\n", cfg.MasterKeyPath())
	}

	store, err := gormstore.Open(cfg.Database.Driver, cfg.DataSource())
	if err != nil {
		return fail(err)
	}
	defer store.Close()
	if err := store.Migrate(context.Background()); err != nil {
		return fail(fmt.Errorf("migrate: %w", err))
	}
	fmt.Printf("database ready  %s (%s)\n", cfg.Database.Driver, cfg.DataSource())

	if *adminToken {
		application, err := openApp(cfgPath)
		if err != nil {
			return fail(err)
		}
		defer application.Close()
		plaintext, tok, err := application.tokens.Create(context.Background(), domain.SystemActor(),
			"admin", []string{"**"}, []string{"read", "write", "delete", "admin"}, 0)
		if err != nil {
			return fail(err)
		}
		fmt.Printf("\nadmin token (shown once, store it now):\n  %s\n", plaintext)
		fmt.Printf("  scopes=%v perms=%v\n", tok.Scopes, tok.Perms)
	}

	fmt.Printf("\nnext: ezstore token create --name agent-a --scopes 'team/**' --perms read,write\n")
	return 0
}

// rewriteDatabase persists driver/dsn overrides back into the config file by
// rewriting the [database] section. It keeps the file human readable instead of
// marshalling the whole struct.
func rewriteDatabase(cfgPath string, cfg *config.Config) error {
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	updated := replaceSection(string(raw), "[database]", fmt.Sprintf(
		"[database]\ndriver = %q\ndsn = %q\n", cfg.Database.Driver, cfg.Database.DSN))
	return os.WriteFile(cfgPath, []byte(updated), 0o600)
}

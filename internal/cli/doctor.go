package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"ezstore/internal/config"
	"ezstore/internal/keyring"
)

var errMissingToken = errors.New("EZSTORE_TOKEN is not set: the mcp command needs a token to act as")

func cmdDoctor(cfgPath string, args []string) int {
	fs := newFlagSet("doctor")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	fmt.Println("ezstore doctor")
	fmt.Printf("  version      %s\n", Version)

	warnings := 0
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Printf("  config       FAIL %v\n", err)
		return 1
	}
	fmt.Printf("  config       %s\n", cfg.Path)
	fmt.Printf("  driver       %s\n", cfg.Database.Driver)
	fmt.Printf("  dsn          %s\n", maskDSN(cfg.DataSource()))
	fmt.Printf("  retain       %s\n", describeRetain(cfg.Security.RetainVersions))

	keyPath := cfg.MasterKeyPath()
	if _, statErr := os.Stat(keyPath); statErr != nil {
		fmt.Printf("  master key   FAIL %v\n", statErr)
		return 1
	}
	if _, err := keyring.Load(keyPath); err != nil {
		fmt.Printf("  master key   FAIL %v\n", err)
		return 1
	}
	wrapped := "raw (0600)"
	if os.PathSeparator == '\\' {
		wrapped = "DPAPI wrapped"
	}
	fmt.Printf("  master key   ok, %s\n", wrapped)

	application, err := openApp(cfgPath)
	if err != nil {
		fmt.Printf("  database     FAIL %v\n", err)
		return 1
	}
	defer application.Close()

	if err := application.store.Ping(context.Background()); err != nil {
		fmt.Printf("  database     FAIL ping: %v\n", err)
		return 1
	}
	fmt.Printf("  database     ok, dialect=%s\n", application.store.Dialect())

	secrets, err := application.store.Secrets().List(context.Background(), "", 0)
	if err == nil {
		fmt.Printf("  secrets      %d\n", len(secrets))
	}
	tokens, err := application.tokens.List(context.Background(), systemActor())
	if err == nil {
		fmt.Printf("  tokens       %d\n", len(tokens))
	}
	if count, err := application.audit.Verify(context.Background(), systemActor()); err == nil {
		fmt.Printf("  audit chain  ok, %d entries\n", count)
	} else {
		fmt.Printf("  audit chain  FAIL %v\n", err)
		return 1
	}

	if !strings.HasPrefix(cfg.Server.Addr, "127.0.0.1") && !strings.HasPrefix(cfg.Server.Addr, "localhost") {
		fmt.Printf("  warning      server.addr %s is not loopback; put a TLS terminator in front\n", cfg.Server.Addr)
		warnings++
	}
	if os.Getenv(keyring.EnvMasterKey) != "" {
		fmt.Println("  warning      EZSTORE_MASTER_KEY overrides the key file; this is the weakest mode")
		warnings++
	}
	if warnings == 0 {
		fmt.Println("  result       ok")
	} else {
		fmt.Printf("  result       ok with %d warning(s)\n", warnings)
	}
	return 0
}

func describeRetain(n int) string {
	if n == 0 {
		return "keep all versions"
	}
	return fmt.Sprintf("keep newest %d versions", n)
}

func maskDSN(dsn string) string {
	at := strings.LastIndex(dsn, "@")
	colon := strings.Index(dsn, ":")
	if at > 0 && colon > 0 && colon < at {
		return dsn[:colon+1] + "***" + dsn[at:]
	}
	return dsn
}

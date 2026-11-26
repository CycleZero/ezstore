// Package cli implements the ezstore command line. Commands run in-process
// against the service layer, so the local operator never needs the HTTP server
// to be up.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"ezstore/internal/config"
	"ezstore/internal/crypto"
	"ezstore/internal/keyring"
	"ezstore/internal/repository"
	"ezstore/internal/repository/gormstore"
	"ezstore/internal/service"
)

// Version is overridden at build time with -ldflags "-X ezstore/internal/cli.Version=...".
var Version = "0.1.0"

const usageText = `ezstore - encrypted secret store with versioning and multi-agent scopes

Usage:
  ezstore [-c FILE] <command> [arguments]

Commands:
  init                     create config, master key and database schema
  serve                    start the Gin HTTP API
  mcp                      start the MCP stdio server (requires EZSTORE_TOKEN)
  secret set <name>        store a new version (value from prompt, stdin or --value)
  secret get <name>        print a secret value
  secret ls                list secret names and metadata
  secret rm <name>         soft delete a secret (--purge to erase history)
  secret history <name>    list versions of a secret
  secret rollback <name>   restore an old version as a new version
  token create             issue an API token
  token ls                 list tokens
  token rm                 revoke a token
  audit tail               show the newest audit entries
  audit verify             verify the audit hash chain
  doctor                   check configuration, key and database
  version                  print the version

Global flags:
  -c, --config FILE        config file (default ezstore.toml)

Environment:
  EZSTORE_MASTER_KEY       master key as hex/base64, overrides the key file
  EZSTORE_TOKEN            token used by the mcp command
  EZSTORE_DEBUG            enable verbose logging
`

// Main is the process entry point. It returns the exit code.
func Main(args []string) int {
	cfgPath := config.DefaultFileName
	rest := args

	for len(rest) > 0 {
		switch rest[0] {
		case "-c", "--config":
			if len(rest) < 2 {
				fmt.Fprintln(os.Stderr, "ezstore: --config needs a file argument")
				return 2
			}
			cfgPath, rest = rest[1], rest[2:]
			continue
		case "-h", "--help", "help":
			fmt.Fprint(os.Stdout, usageText)
			return 0
		case "--version":
			fmt.Fprintln(os.Stdout, Version)
			return 0
		}
		break
	}

	if len(rest) == 0 {
		fmt.Fprint(os.Stderr, usageText)
		return 2
	}

	cmd, tail := rest[0], rest[1:]
	switch cmd {
	case "init":
		return cmdInit(cfgPath, tail)
	case "serve":
		return cmdServe(cfgPath, tail)
	case "mcp":
		return cmdMCP(cfgPath, tail)
	case "secret":
		return cmdSecret(cfgPath, tail)
	case "token":
		return cmdToken(cfgPath, tail)
	case "audit":
		return cmdAudit(cfgPath, tail)
	case "doctor":
		return cmdDoctor(cfgPath, tail)
	case "version":
		fmt.Fprintln(os.Stdout, Version)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "ezstore: unknown command %q\n\n", cmd)
		fmt.Fprint(os.Stderr, usageText)
		return 2
	}
}

// app bundles an opened configuration, database and service set.
type app struct {
	cfg   *config.Config
	store repository.Store

	secrets *service.SecretService
	tokens  *service.TokenService
	audit   *service.AuditService
}

// openApp loads the config, unwraps the master key, opens the database and
// wires every service.
func openApp(cfgPath string) (*app, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	key, _, err := keyring.Ensure(cfg.MasterKeyPath())
	if err != nil {
		return nil, err
	}
	cipher, err := crypto.New(key)
	if err != nil {
		return nil, err
	}
	store, err := gormstore.Open(cfg.Database.Driver, cfg.DataSource())
	if err != nil {
		return nil, err
	}
	if err := store.Migrate(context.Background()); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("migrate database: %w", err)
	}
	audit := service.NewAuditService(store)
	return &app{
		cfg:     cfg,
		store:   store,
		secrets: service.NewSecretService(store, cipher, audit, cfg.Security.RetainVersions),
		tokens:  service.NewTokenService(store),
		audit:   audit,
	}, nil
}

func (a *app) Close() error { return a.store.Close() }

func fail(err error) int {
	fmt.Fprintf(os.Stderr, "ezstore: %v\n", err)
	return 1
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

// parseInterspersed parses flags that may appear before or after positional
// arguments, and returns the positional arguments.
//
// Go's flag package stops at the first non-flag argument, which would silently
// turn "secret set team/key --tag env=prod" into one flagless call with
// "--tag" and "env=prod" as extra positionals. Everything here is written in
// the natural order, so the parser has to allow it.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			positional = append(positional, args[i+1:]...)
			i = len(args)
		case len(arg) > 1 && strings.HasPrefix(arg, "-"):
			name := strings.TrimLeft(arg, "-")
			if strings.IndexByte(name, '=') >= 0 {
				flags = append(flags, arg)
				continue
			}
			def := fs.Lookup(name)
			if def == nil {
				flags = append(flags, arg)
				continue
			}
			if boolFlag, ok := def.Value.(interface{ IsBoolFlag() bool }); ok && boolFlag.IsBoolFlag() {
				flags = append(flags, arg)
				continue
			}
			flags = append(flags, arg)
			if i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
		default:
			positional = append(positional, arg)
		}
	}
	if err := fs.Parse(flags); err != nil {
		return nil, err
	}
	return append(positional, fs.Args()...), nil
}

// tagFlags collects repeated --tag key=value flags.
type tagFlags map[string]string

func (t tagFlags) String() string { return "" }

func (t tagFlags) Set(raw string) error {
	key, value, ok := strings.Cut(raw, "=")
	if !ok || key == "" {
		return fmt.Errorf("tag must be key=value, got %q", raw)
	}
	t[key] = value
	return nil
}

// readValue reads a secret value from --value, from stdin, or from a hidden
// terminal prompt. It never accepts the value as a bare argument, because argv
// is visible to every process on the machine.
func readValue(fromStdin bool, inline string) ([]byte, error) {
	if inline != "" {
		return []byte(inline), nil
	}
	if fromStdin {
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		return trimTrailingNewline(raw), nil
	}
	info, err := os.Stdin.Stat()
	if err == nil && info.Mode()&os.ModeCharDevice != 0 {
		return readPassword()
	}
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, err
	}
	return trimTrailingNewline(raw), nil
}

// trimTrailingNewline drops one trailing line ending. Piping a value through a
// shell almost always adds one, and a secret that silently ends in "\r\n" is a
// bug that is very hard to see.
func trimTrailingNewline(raw []byte) []byte {
	if len(raw) >= 2 && raw[len(raw)-2] == '\r' && raw[len(raw)-1] == '\n' {
		return raw[:len(raw)-2]
	}
	if len(raw) >= 1 && raw[len(raw)-1] == '\n' {
		return raw[:len(raw)-1]
	}
	return raw
}

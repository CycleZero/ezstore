// Package config loads the ezstore TOML configuration and resolves every
// relative path against the directory that holds the config file.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// DefaultFileName is looked up in the working directory when --config is unset.
const DefaultFileName = "ezstore.toml"

// Config is the whole ezstore configuration file.
type Config struct {
	Server   Server   `toml:"server"`
	Database Database `toml:"database"`
	Security Security `toml:"security"`

	// Path and BaseDir are derived, never written to disk.
	Path    string `toml:"-"`
	BaseDir string `toml:"-"`
}

// Server configures the Gin HTTP listener.
type Server struct {
	Addr string `toml:"addr"`
}

// Database selects the GORM driver and DSN.
type Database struct {
	// Driver is "sqlite" or "mysql".
	Driver string `toml:"driver"`
	// DSN is a file path for sqlite, or a go-sql-driver/mysql DSN for mysql.
	DSN string `toml:"dsn"`
}

// Security configures key storage and history retention.
type Security struct {
	MasterKeyFile string `toml:"master_key_file"`
	// RetainVersions keeps only the newest N versions per secret. 0 keeps all.
	RetainVersions int `toml:"retain_versions"`
}

// Default returns a config with every default applied.
func Default() Config {
	return Config{
		Server:   Server{Addr: "127.0.0.1:8787"},
		Database: Database{Driver: "sqlite", DSN: "ezstore.db"},
		Security: Security{MasterKeyFile: "master.key", RetainVersions: 0},
	}
}

// Load reads and validates the config at path.
func Load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("config %s not found: run 'ezstore init' first", abs)
		}
		return nil, err
	}
	cfg := Default()
	if _, err := toml.Decode(string(raw), &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", abs, err)
	}
	cfg.Path = abs
	cfg.BaseDir = filepath.Dir(abs)
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// WriteDefault writes a commented starter config to path.
func WriteDefault(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("config %s already exists", path)
	}
	return os.WriteFile(path, []byte(defaultTemplate), 0o600)
}

func (c *Config) normalize() error {
	if c.Database.Driver == "" {
		c.Database.Driver = "sqlite"
	}
	switch strings.ToLower(c.Database.Driver) {
	case "sqlite", "sqlite3":
		c.Database.Driver = "sqlite"
	case "mysql":
		c.Database.Driver = "mysql"
	default:
		return fmt.Errorf("database.driver %q must be sqlite or mysql", c.Database.Driver)
	}
	if c.Database.DSN == "" {
		return errors.New("database.dsn is empty")
	}
	if c.Security.MasterKeyFile == "" {
		c.Security.MasterKeyFile = "master.key"
	}
	if c.Security.RetainVersions < 0 {
		return errors.New("security.retain_versions must be >= 0")
	}
	if c.Server.Addr == "" {
		c.Server.Addr = "127.0.0.1:8787"
	}
	return nil
}

// MasterKeyPath returns the absolute master key path.
func (c *Config) MasterKeyPath() string {
	if filepath.IsAbs(c.Security.MasterKeyFile) {
		return c.Security.MasterKeyFile
	}
	return filepath.Join(c.BaseDir, c.Security.MasterKeyFile)
}

// DataSource returns the DSN to hand to the GORM driver. Relative sqlite paths
// are resolved against the config directory. MySQL DSNs get parseTime and
// charset filled in when the operator left them out, because scanning
// timestamps and storing non-ASCII tags both depend on them.
func (c *Config) DataSource() string {
	if c.Database.Driver != "sqlite" {
		return ensureMySQLParams(c.Database.DSN)
	}
	dsn := c.Database.DSN
	if strings.HasPrefix(dsn, "file:") || dsn == ":memory:" {
		return dsn
	}
	if !filepath.IsAbs(dsn) {
		dsn = filepath.Join(c.BaseDir, dsn)
	}
	return dsn
}

func ensureMySQLParams(dsn string) string {
	lower := strings.ToLower(dsn)
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	var add []string
	if !strings.Contains(lower, "parsetime=") {
		add = append(add, "parseTime=true")
	}
	if !strings.Contains(lower, "charset=") {
		add = append(add, "charset=utf8mb4")
	}
	if len(add) == 0 {
		return dsn
	}
	return dsn + sep + strings.Join(add, "&")
}

const defaultTemplate = `# ezstore configuration
# All relative paths are resolved against this file's directory.

[server]
# Gin HTTP API listener. Keep it on loopback unless a reverse proxy fronts it.
addr = "127.0.0.1:8787"

[database]
# "sqlite" (embedded, zero setup) or "mysql".
driver = "sqlite"
# sqlite: file path. mysql: user:pass@tcp(127.0.0.1:3306)/ezstore?charset=utf8mb4&parseTime=True
dsn = "ezstore.db"

[security]
# Master key file. On Windows it is DPAPI-wrapped; elsewhere it is 0600.
master_key_file = "master.key"
# 0 keeps every version forever. N keeps the newest N versions per secret.
retain_versions = 0
`

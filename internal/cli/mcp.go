package cli

import (
	"context"
	"log"
	"os"

	"ezstore/internal/transport/mcp"
)

func cmdMCP(cfgPath string, args []string) int {
	fs := newFlagSet("mcp")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	plaintext := os.Getenv("EZSTORE_TOKEN")
	if plaintext == "" {
		return fail(errMissingToken)
	}

	application, err := openApp(cfgPath)
	if err != nil {
		return fail(err)
	}
	defer application.Close()

	actor, err := application.tokens.Authenticate(context.Background(), plaintext)
	if err != nil {
		return fail(err)
	}

	logger := log.New(os.Stderr, "ezstore-mcp: ", log.LstdFlags)
	server := mcp.New(mcp.Options{
		Secrets: application.secrets,
		Tokens:  application.tokens,
		Audit:   application.audit,
		Actor:   actor,
		Version: Version,
		In:      os.Stdin,
		Out:     os.Stdout,
		Log:     logger,
	})
	logger.Printf("serving as token %s (scopes=%v perms=%v)", actor.Name, actor.Scopes, actor.Perms)
	if err := server.Run(context.Background()); err != nil {
		return fail(err)
	}
	return 0
}

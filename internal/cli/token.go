package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"ezstore/internal/domain"
)

func cmdToken(cfgPath string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ezstore token <create|ls|rm> [arguments]")
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "create":
		return cmdTokenCreate(cfgPath, rest)
	case "ls", "list":
		return cmdTokenList(cfgPath, rest)
	case "rm", "revoke":
		return cmdTokenRevoke(cfgPath, rest)
	default:
		fmt.Fprintf(os.Stderr, "ezstore: unknown token subcommand %q\n", sub)
		return 2
	}
}

func cmdTokenCreate(cfgPath string, args []string) int {
	fs := newFlagSet("token create")
	name := fs.String("name", "", "unique token name")
	scopes := fs.String("scopes", "", "comma separated scope globs, for example 'team/**,shared/*'")
	perms := fs.String("perms", "read", "comma separated permissions: read,write,delete,admin")
	ttl := fs.Duration("ttl", 0, "optional lifetime, for example 720h")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *name == "" || *scopes == "" {
		fmt.Fprintln(os.Stderr, "usage: ezstore token create --name NAME --scopes GLOB[,GLOB] [--perms ...] [--ttl 720h]")
		return 2
	}

	application, err := openApp(cfgPath)
	if err != nil {
		return fail(err)
	}
	defer application.Close()

	plaintext, tok, err := application.tokens.Create(context.Background(), domain.SystemActor(),
		*name, splitList(*scopes), splitList(*perms), *ttl)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("token %s\n  %s\n", tok.Name, plaintext)
	fmt.Printf("  scopes=%s perms=%s", strings.Join(tok.Scopes, ","), strings.Join(tok.Perms, ","))
	if tok.ExpiresAt != nil {
		fmt.Printf(" expires=%s", tok.ExpiresAt.Format(time.RFC3339))
	}
	fmt.Println()
	fmt.Println("\nThe plaintext token is shown once and cannot be recovered.")
	return 0
}

func cmdTokenList(cfgPath string, args []string) int {
	fs := newFlagSet("token ls")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	application, err := openApp(cfgPath)
	if err != nil {
		return fail(err)
	}
	defer application.Close()

	tokens, err := application.tokens.List(context.Background(), domain.SystemActor())
	if err != nil {
		return fail(err)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSCOPES\tPERMS\tCREATED\tEXPIRES\tENABLED")
	for _, tok := range tokens {
		expires := "never"
		if tok.ExpiresAt != nil {
			expires = tok.ExpiresAt.Local().Format(time.RFC3339)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%t\n", tok.Name,
			strings.Join(tok.Scopes, ","), strings.Join(tok.Perms, ","),
			tok.CreatedAt.Local().Format(time.RFC3339), expires, tok.Enabled)
	}
	_ = tw.Flush()
	return 0
}

func cmdTokenRevoke(cfgPath string, args []string) int {
	fs := newFlagSet("token rm")
	name := fs.String("name", "", "token name to revoke")
	positional, err := parseInterspersed(fs, args)
	if err != nil {
		return 2
	}
	if *name == "" && len(positional) > 0 {
		*name = positional[0]
	}
	if *name == "" {
		fmt.Fprintln(os.Stderr, "usage: ezstore token rm --name NAME")
		return 2
	}

	application, err := openApp(cfgPath)
	if err != nil {
		return fail(err)
	}
	defer application.Close()

	if err := application.tokens.Revoke(context.Background(), domain.SystemActor(), *name); err != nil {
		return fail(err)
	}
	fmt.Printf("token %s revoked\n", *name)
	return 0
}

func splitList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

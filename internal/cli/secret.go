package cli

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"ezstore/internal/domain"
)

func cmdSecret(cfgPath string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ezstore secret <set|get|ls|rm|history|rollback> [arguments]")
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "set":
		return cmdSecretSet(cfgPath, rest)
	case "get":
		return cmdSecretGet(cfgPath, rest)
	case "ls", "list":
		return cmdSecretList(cfgPath, rest)
	case "rm", "delete":
		return cmdSecretDelete(cfgPath, rest)
	case "history":
		return cmdSecretHistory(cfgPath, rest)
	case "rollback":
		return cmdSecretRollback(cfgPath, rest)
	default:
		fmt.Fprintf(os.Stderr, "ezstore: unknown secret subcommand %q\n", sub)
		return 2
	}
}

func cmdSecretSet(cfgPath string, args []string) int {
	flags := newFlagSet("secret set")
	tags := tagFlags{}
	flags.Var(tags, "tag", "tag in key=value form, repeatable")
	inline := flags.String("value", "", "value inline (prefer the prompt or --stdin)")
	fromStdin := flags.Bool("stdin", false, "read the value from stdin")
	positional, err := parseInterspersed(flags, args)
	if err != nil {
		return 2
	}
	if len(positional) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ezstore secret set <name> [--tag k=v] [--stdin]")
		return 2
	}
	name := positional[0]

	application, err := openApp(cfgPath)
	if err != nil {
		return fail(err)
	}
	defer application.Close()

	value, err := readValue(*fromStdin, *inline)
	if err != nil {
		return fail(err)
	}
	version, err := application.secrets.Put(context.Background(), domain.SystemActor(), name, value, tags)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("%s  version %d\n", name, version)
	return 0
}

func cmdSecretGet(cfgPath string, args []string) int {
	flags := newFlagSet("secret get")
	version := flags.Int64("version", 0, "specific version (default current)")
	positional, err := parseInterspersed(flags, args)
	if err != nil {
		return 2
	}
	if len(positional) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ezstore secret get <name> [--version N]")
		return 2
	}
	name := positional[0]

	application, err := openApp(cfgPath)
	if err != nil {
		return fail(err)
	}
	defer application.Close()

	value, err := application.secrets.Get(context.Background(), domain.SystemActor(), name, *version)
	if err != nil {
		return fail(err)
	}
	if _, err := os.Stdout.Write(value.Value); err != nil {
		return fail(err)
	}
	if len(value.Value) == 0 || value.Value[len(value.Value)-1] != '\n' {
		fmt.Fprintln(os.Stdout)
	}
	return 0
}

func cmdSecretList(cfgPath string, args []string) int {
	flags := newFlagSet("secret ls")
	prefix := flags.String("prefix", "", "only names under this prefix")
	tag := flags.String("tag", "", "filter by tag: key or key=value")
	limit := flags.Int("limit", 0, "maximum number of names")
	if _, err := parseInterspersed(flags, args); err != nil {
		return 2
	}

	application, err := openApp(cfgPath)
	if err != nil {
		return fail(err)
	}
	defer application.Close()

	items, err := application.secrets.List(context.Background(), domain.SystemActor(), *prefix, *tag, *limit)
	if err != nil {
		return fail(err)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tVERSION\tUPDATED\tTAGS")
	for _, item := range items {
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\n", item.Name, item.CurrentVersion,
			item.UpdatedAt.Local().Format(time.RFC3339), formatTags(item.Tags))
	}
	_ = tw.Flush()
	return 0
}

func cmdSecretDelete(cfgPath string, args []string) int {
	flags := newFlagSet("secret rm")
	purge := flags.Bool("purge", false, "also erase every version permanently")
	confirm := flags.Bool("yes", false, "confirm a purge")
	positional, err := parseInterspersed(flags, args)
	if err != nil {
		return 2
	}
	if len(positional) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ezstore secret rm <name> [--purge --yes]")
		return 2
	}
	name := positional[0]
	if *purge && !*confirm {
		fmt.Fprintln(os.Stderr, "ezstore: --purge erases history; re-run with --yes to confirm")
		return 2
	}

	application, err := openApp(cfgPath)
	if err != nil {
		return fail(err)
	}
	defer application.Close()

	if err := application.secrets.Delete(context.Background(), domain.SystemActor(), name, *purge); err != nil {
		return fail(err)
	}
	if *purge {
		fmt.Printf("%s  purged\n", name)
	} else {
		fmt.Printf("%s  soft deleted (history kept)\n", name)
	}
	return 0
}

func cmdSecretHistory(cfgPath string, args []string) int {
	flags := newFlagSet("secret history")
	limit := flags.Int("limit", 0, "maximum number of versions")
	positional, err := parseInterspersed(flags, args)
	if err != nil {
		return 2
	}
	if len(positional) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ezstore secret history <name> [--limit N]")
		return 2
	}
	name := positional[0]

	application, err := openApp(cfgPath)
	if err != nil {
		return fail(err)
	}
	defer application.Close()

	versions, err := application.secrets.History(context.Background(), domain.SystemActor(), name, *limit)
	if err != nil {
		return fail(err)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "VERSION\tCREATED\tBY\tCHECKSUM")
	for _, item := range versions {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", item.Version,
			item.CreatedAt.Local().Format(time.RFC3339), item.CreatedBy, short(item.Checksum))
	}
	_ = tw.Flush()
	return 0
}

func cmdSecretRollback(cfgPath string, args []string) int {
	flags := newFlagSet("secret rollback")
	version := flags.Int64("version", 0, "version to restore")
	positional, err := parseInterspersed(flags, args)
	if err != nil {
		return 2
	}
	if len(positional) == 0 || *version <= 0 {
		fmt.Fprintln(os.Stderr, "usage: ezstore secret rollback <name> --version N")
		return 2
	}
	name := positional[0]

	application, err := openApp(cfgPath)
	if err != nil {
		return fail(err)
	}
	defer application.Close()

	created, err := application.secrets.Rollback(context.Background(), domain.SystemActor(), name, *version)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("%s  restored v%d as v%d\n", name, *version, created)
	return 0
}

func formatTags(tags map[string]string) string {
	if len(tags) == 0 {
		return "-"
	}
	out := ""
	for k, v := range tags {
		if out != "" {
			out += ","
		}
		out += k + "=" + v
	}
	return out
}

func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

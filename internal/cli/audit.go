package cli

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"ezstore/internal/domain"
)

func cmdAudit(cfgPath string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ezstore audit <tail|verify> [arguments]")
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "tail":
		return cmdAuditTail(cfgPath, rest)
	case "verify":
		return cmdAuditVerify(cfgPath, rest)
	default:
		fmt.Fprintf(os.Stderr, "ezstore: unknown audit subcommand %q\n", sub)
		return 2
	}
}

func cmdAuditTail(cfgPath string, args []string) int {
	fs := newFlagSet("audit tail")
	limit := fs.Int("limit", 30, "number of entries")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	application, err := openApp(cfgPath)
	if err != nil {
		return fail(err)
	}
	defer application.Close()

	entries, err := application.audit.Tail(context.Background(), domain.SystemActor(), *limit)
	if err != nil {
		return fail(err)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SEQ\tTIME\tACTOR\tOP\tNAME\tOK\tDETAIL")
	for _, e := range entries {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%t\t%s\n", e.Seq,
			e.TS.Local().Format(time.RFC3339), e.Actor, e.Op, e.Name, e.OK, e.Detail)
	}
	_ = tw.Flush()
	return 0
}

func cmdAuditVerify(cfgPath string, args []string) int {
	fs := newFlagSet("audit verify")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	application, err := openApp(cfgPath)
	if err != nil {
		return fail(err)
	}
	defer application.Close()

	count, err := application.audit.Verify(context.Background(), domain.SystemActor())
	if err != nil {
		return fail(err)
	}
	fmt.Printf("audit chain intact: %d entries verified\n", count)
	return 0
}

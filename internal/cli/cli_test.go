package cli

import (
	"flag"
	"testing"
)

func TestParseInterspersedAcceptsFlagsAfterPositionals(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	tag := fs.String("tag", "", "")
	fromStdin := fs.Bool("stdin", false, "")

	positional, err := parseInterspersed(fs, []string{"team/key", "--tag", "env=prod", "--stdin"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(positional) != 1 || positional[0] != "team/key" {
		t.Fatalf("positional = %v, want [team/key]", positional)
	}
	if *tag != "env=prod" {
		t.Fatalf("tag = %q", *tag)
	}
	if !*fromStdin {
		t.Fatal("stdin flag not set")
	}
}

func TestParseInterspersedAcceptsFlagsBeforePositionals(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	limit := fs.Int("limit", 0, "")

	positional, err := parseInterspersed(fs, []string{"--limit", "5", "team/key"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if *limit != 5 {
		t.Fatalf("limit = %d", *limit)
	}
	if len(positional) != 1 || positional[0] != "team/key" {
		t.Fatalf("positional = %v", positional)
	}
}

func TestParseInterspersedHandlesEqualsForm(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	name := fs.String("name", "", "")

	if _, err := parseInterspersed(fs, []string{"--name=agent-a"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if *name != "agent-a" {
		t.Fatalf("name = %q", *name)
	}
}

func TestTrimTrailingNewline(t *testing.T) {
	cases := []struct{ in, want string }{
		{"secret", "secret"},
		{"secret\n", "secret"},
		{"secret\r\n", "secret"},
		{"secret\r\n\r\n", "secret\r\n"},
		{"\n", ""},
	}
	for _, tc := range cases {
		if got := string(trimTrailingNewline([]byte(tc.in))); got != tc.want {
			t.Errorf("trimTrailingNewline(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

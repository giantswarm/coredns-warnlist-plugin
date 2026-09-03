package warnlist

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
)

func writeDomainFile(t *testing.T, lines string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(path, []byte(lines), 0o600); err != nil {
		t.Fatalf("write domain file: %v", err)
	}
	return path
}

func TestParseArguments(t *testing.T) {
	file := writeDomainFile(t, "example.org\n")

	testCases := []struct {
		name        string
		corefile    string
		wantErr     bool
		wantSource  string
		wantType    string
		wantFormat  string
		wantSubdoms bool
	}{
		{
			name:     "no source is an error",
			corefile: `warnlist`,
			wantErr:  true,
		},
		{
			name:     "unknown file format is an error",
			corefile: "warnlist {\n file " + file + " csv\n}",
			wantErr:  true,
		},
		{
			name:     "file and url together is an error",
			corefile: "warnlist {\n file " + file + " text\n url https://example.org/hosts hostfile\n}",
			wantErr:  true,
		},
		{
			name:     "match_subdomains must be a bool",
			corefile: "warnlist {\n file " + file + " text\n match_subdomains maybe\n}",
			wantErr:  true,
		},
		{
			name:     "reload must be a duration",
			corefile: "warnlist {\n file " + file + " text\n reload soon\n}",
			wantErr:  true,
		},
		{
			name:        "file source, defaults",
			corefile:    "warnlist {\n file " + file + " text\n}",
			wantSource:  file,
			wantType:    DomainSourceTypeFile,
			wantFormat:  DomainFileFormatTextList,
			wantSubdoms: true,
		},
		{
			name:        "url source, subdomains off",
			corefile:    "warnlist {\n url https://example.org/hosts hostfile\n match_subdomains false\n}",
			wantSource:  "https://example.org/hosts",
			wantType:    DomainSourceTypeURL,
			wantFormat:  DomainFileFormatHostfile,
			wantSubdoms: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tc.corefile)
			opts, err := parseArguments(c)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got options %+v", opts)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if opts.DomainSource != tc.wantSource || opts.DomainSourceType != tc.wantType || opts.FileFormat != tc.wantFormat || opts.MatchSubdomains != tc.wantSubdoms {
				t.Errorf("got %+v", opts)
			}
		})
	}
}

func TestParseArgumentsReloadJitter(t *testing.T) {
	file := writeDomainFile(t, "example.org\n")
	c := caddy.NewTestController("dns", "warnlist {\n file "+file+" text\n reload 10m\n}")
	opts, err := parseArguments(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	lo, hi := 7*time.Minute, 10*time.Minute
	if opts.ReloadPeriod < lo || opts.ReloadPeriod > hi {
		t.Errorf("reload period %s outside the documented -30%% jitter window [%s, %s]", opts.ReloadPeriod, lo, hi)
	}
}

func TestSetup(t *testing.T) {
	file := writeDomainFile(t, "# comment\nexample.org\nexample.net.\n")

	c := caddy.NewTestController("dns", "warnlist {\n file "+file+" text\n}")
	if err := setup(c); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if n := len(dnsserver.GetConfig(c).Plugin); n != 1 {
		t.Fatalf("expected the plugin to be registered once, found %d", n)
	}

	c = caddy.NewTestController("dns", "warnlist {\n file "+filepath.Join(t.TempDir(), "missing.txt")+" text\n}")
	if err := setup(c); err == nil {
		t.Fatal("expected an error for a missing warnlist file")
	}
}

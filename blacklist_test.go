package malicious

import (
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var testBlacklist = []string{
	"example.org",
	"something.evil",
	"coredns.io",
}

func Test_blacklistHits(t *testing.T) {
	var testCases = []struct {
		domain string
		hit    bool
		name   string
	}{
		{
			name:   "case 0: a domain in the list is matched",
			domain: "example.org",
			hit:    true,
		},
		{
			name:   "case 1: a domain not in the list is not matched",
			domain: "this-is-ok.org",
			hit:    false,
		},
	}

	// Create our testing list
	list := NewBlacklist()
	for _, d := range testBlacklist {
		list.Add(d)
	}
	list.Close()

	// Run the test cases
	for i, tc := range testCases {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Log(tc.name)

			hit := list.Contains(tc.domain)
			if !cmp.Equal(tc.hit, hit) {
				t.Fatalf("\n\n%s\n", cmp.Diff(tc.hit, hit))
			}
		})
	}
}

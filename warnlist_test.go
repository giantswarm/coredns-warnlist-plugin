package warnlist

import (
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var testWarnlist = []string{
	"example.org",
	"something.evil",
	"evil.com",
	"something.wicked.test",
	"coredns.io",
}

func Test_warnlistHits(t *testing.T) {
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
	list := NewWarnlist()
	for _, d := range testWarnlist {
		list.Add(d)
	}
	err := list.Close()
	if err != nil {
		t.Fatalf("Error closing warnlist: %v", err)
	}

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

func Test_radixContains(t *testing.T) {
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
		{
			name:   "case 2: a subdomain of a domain in the list is matched",
			domain: "very.evil.com",
			hit:    true,
		},
		{
			name:   "case 3: multiple subdomains of a domain in the list are matched",
			domain: "oh.so.very.evil.com",
			hit:    true,
		},
		{
			name:   "case 4: a similar suffix domain is not matched",
			domain: "devil.com",
			hit:    false,
		},
		{
			name:   "case 5: a similar substring is not matched",
			domain: "evil.com.org",
			hit:    false,
		},
	}

	list := NewRadixWarnlist()
	for _, d := range testWarnlist {
		list.Add(d)
	}
	err := list.Close()
	if err != nil {
		t.Fatalf("Error closing warnlist: %v", err)
	}

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

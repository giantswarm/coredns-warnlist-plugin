package malicious

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/alecthomas/mph"
	iradix "github.com/hashicorp/go-immutable-radix"
)

type Blacklist interface {
	Add(key string)
	Contains(key string) bool
	Close() error
	Len() int
	Open()
}

func NewBlacklist() Blacklist {
	b := &GoMapBlacklist{}
	b.Open()
	return b
}

func NewRadixBlacklist() Blacklist {
	b := &RadixBlacklist{}
	b.Open()
	return b
}

type RadixBlacklist struct {
	blacklist *iradix.Tree
}

func (r *RadixBlacklist) Add(key string) {
	// Add the domain in reverse so we can pretend it's a prefix.
	key = reverseString(key)

	b, _, _ := r.blacklist.Insert([]byte(key), 1)
	r.blacklist = b
}

func (r *RadixBlacklist) Contains(key string) bool {
	keyR := reverseString(key)

	m, _, ok := r.blacklist.Root().LongestPrefix([]byte(keyR))
	if !ok {
		return false
	}
	return isFullPrefixMatch(keyR, string(m))
}

func (r *RadixBlacklist) Close() error {
	// Nothing to do to close an iradix
	return nil
}

func (r *RadixBlacklist) Len() int {
	return r.blacklist.Len()
}

func (r *RadixBlacklist) Open() {
	tree := iradix.New()
	r.blacklist = tree
}

// Shamelessly taken from https://stackoverflow.com/a/34521190
func reverseString(s string) string {
	size := len(s)
	buf := make([]byte, size)
	for start := 0; start < size; {
		r, n := utf8.DecodeRuneInString(s[start:])
		start += n
		utf8.EncodeRune(buf[size-start:], r)
	}
	return string(buf)
}

func isFullPrefixMatch(input string, match string) bool {
	// Either we matched the full input,
	// or this is a subdomain, so the next character should be "."
	return len(input) == len(match) || string(input[len(match)]) == "."
}

// Go Map

type GoMapBlacklist struct {
	blacklist map[string]struct{}
}

func (m *GoMapBlacklist) Add(key string) {
	m.blacklist[key] = struct{}{}
}

func (m *GoMapBlacklist) Contains(key string) bool {
	_, ok := m.blacklist[key]
	return ok
}

func (m *GoMapBlacklist) Close() error {
	// Nothing to do to close a map
	return nil
}

func (m *GoMapBlacklist) Len() int {
	return len(m.blacklist)
}

func (m *GoMapBlacklist) Open() {
	m.blacklist = make(map[string]struct{})
}

// MPH

type MPHBlacklist struct {
	blacklist *mph.CHD
	builder   *mph.CHDBuilder
}

func (m *MPHBlacklist) Add(key string) {
	m.builder.Add([]byte(key), []byte(""))
}

func (m *MPHBlacklist) Contains(key string) bool {
	hit := m.blacklist.Get([]byte(key))
	return hit != nil
}

func (m *MPHBlacklist) Close() error {
	blacklist, err := m.builder.Build()
	if err != nil {
		if strings.Contains(err.Error(), "failed to find a collision-free hash function") {
			// Special case where there are 2^n objects in the mph blacklist
			m.Add("some.bogus")
			msg := "when using the MPH backend, the number of items must not be a power of 2. The domain \"some.bogus\" has been added to allow building the cache."
			log.Warning(msg)
			blacklist, err = m.builder.Build()
		}
	}
	m.builder = nil
	m.blacklist = blacklist

	return err
}

func (m *MPHBlacklist) Len() int {
	return m.blacklist.Len()
}

func (m *MPHBlacklist) Open() {
	m.builder = mph.Builder()
}

func rebuildBlacklist(m *Malicious) {
	// Rebuild the cache for the blacklist
	blacklist, err := buildCacheFromFile(m.Options)
	if err != nil {
		log.Errorf("error rebuilding blacklist: %v#", err)

		if m.serverName != "" {
			reloadsFailedCount.WithLabelValues(m.serverName).Inc()
		}

		// Don't update the existing blacklist
	} else {
		reloadTime := time.Now()
		m.blacklist = blacklist
		m.lastReloadTime = reloadTime
	}
	if m.serverName != "" {
		blacklistSize.WithLabelValues(m.serverName).Set(float64(m.blacklist.Len()))
	}

}

func buildCacheFromFile(options PluginOptions) (Blacklist, error) {
	// Print a log message with the time it took to build the cache
	defer logTime("Building blacklist cache took %s", time.Now())

	blacklist := NewBlacklist()
	for domain := range domainsFromSource(options.DomainSource, options.DomainSourceType, options.FileFormat) {
		blacklist.Add(domain)
	}

	err := blacklist.Close()
	if err == nil {
		log.Infof("added %d domains to blacklist", blacklist.Len())
	}

	return blacklist, err
}

// Prints the elapsed time in the pre-formatted message
func logTime(msg string, since time.Time) {
	elapsed := time.Since(since)
	msg = fmt.Sprintf(msg, elapsed)
	log.Info(msg)
}

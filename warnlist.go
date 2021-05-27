package warnlist

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/alecthomas/mph"
	iradix "github.com/hashicorp/go-immutable-radix"
)

type Warnlist interface {
	Add(key string)
	Contains(key string) bool
	Close() error
	Len() int
	Open()
}

func NewWarnlist() Warnlist {
	b := &GoMapWarnlist{}
	b.Open()
	return b
}

func NewRadixWarnlist() Warnlist {
	b := &RadixWarnlist{}
	b.Open()
	return b
}

type RadixWarnlist struct {
	warnlist *iradix.Tree
}

func (r *RadixWarnlist) Add(key string) {
	// Add the domain in reverse so we can pretend it's a prefix.
	key = reverseString(key)

	b, _, _ := r.warnlist.Insert([]byte(key), 1)
	r.warnlist = b
}

func (r *RadixWarnlist) Contains(key string) bool {
	keyR := reverseString(key)

	m, _, ok := r.warnlist.Root().LongestPrefix([]byte(keyR))
	if !ok {
		return false
	}
	return isFullPrefixMatch(keyR, string(m))
}

func (r *RadixWarnlist) Close() error {
	// Nothing to do to close an iradix
	return nil
}

func (r *RadixWarnlist) Len() int {
	return r.warnlist.Len()
}

func (r *RadixWarnlist) Open() {
	tree := iradix.New()
	r.warnlist = tree
}

// Go Map

type GoMapWarnlist struct {
	warnlist map[string]struct{}
}

func (m *GoMapWarnlist) Add(key string) {
	m.warnlist[key] = struct{}{}
}

func (m *GoMapWarnlist) Contains(key string) bool {
	_, ok := m.warnlist[key]
	return ok
}

func (m *GoMapWarnlist) Close() error {
	// Nothing to do to close a map
	return nil
}

func (m *GoMapWarnlist) Len() int {
	return len(m.warnlist)
}

func (m *GoMapWarnlist) Open() {
	m.warnlist = make(map[string]struct{})
}

// MPH

type MPHWarnlist struct {
	warnlist *mph.CHD
	builder  *mph.CHDBuilder
}

func (m *MPHWarnlist) Add(key string) {
	m.builder.Add([]byte(key), []byte(""))
}

func (m *MPHWarnlist) Contains(key string) bool {
	hit := m.warnlist.Get([]byte(key))
	return hit != nil
}

func (m *MPHWarnlist) Close() error {
	warnlist, err := m.builder.Build()
	if err != nil {
		if strings.Contains(err.Error(), "failed to find a collision-free hash function") {
			// Special case where there are 2^n objects in the mph warnlist
			m.Add("some.bogus")
			msg := "when using the MPH backend, the number of items must not be a power of 2. The domain \"some.bogus\" has been added to allow building the cache."
			log.Warning(msg)
			warnlist, err = m.builder.Build()
		}
	}
	m.builder = nil
	m.warnlist = warnlist

	return err
}

func (m *MPHWarnlist) Len() int {
	return m.warnlist.Len()
}

func (m *MPHWarnlist) Open() {
	m.builder = mph.Builder()
}

func buildCacheFromFile(options PluginOptions) (Warnlist, error) {
	// Print a log message with the time it took to build the cache
	defer logTime("Building warnlist cache took %s", time.Now())

	var warnlist Warnlist
	{
		if options.MatchSubdomains {
			warnlist = NewRadixWarnlist()
		} else {
			warnlist = NewWarnlist()
		}
	}

	for domain := range domainsFromSource(options.DomainSource, options.DomainSourceType, options.FileFormat) {
		warnlist.Add(domain)
	}

	err := warnlist.Close()
	if err == nil {
		log.Infof("added %d domains to warnlist", warnlist.Len())
	}

	return warnlist, err
}

// isFullPrefixMatch is a radix helper to determine if the prefix match is valid.
func isFullPrefixMatch(input string, match string) bool {
	// Either we matched the full input,
	// or this is a subdomain, so the next character should be "."
	return len(input) == len(match) || string(input[len(match)]) == "."
}

// Prints the elapsed time in the pre-formatted message
func logTime(msg string, since time.Time) {
	elapsed := time.Since(since)
	msg = fmt.Sprintf(msg, elapsed)
	log.Info(msg)
}

func rebuildWarnlist(m *Malicious) {
	// Rebuild the cache for the warnlist
	warnlist, err := buildCacheFromFile(m.Options)
	if err != nil {
		log.Errorf("error rebuilding warnlist: %v#", err)

		if m.serverName != "" {
			reloadsFailedCount.WithLabelValues(m.serverName).Inc()
		}

		// Don't update the existing warnlist
	} else {
		reloadTime := time.Now()
		m.warnlist = warnlist
		m.lastReloadTime = reloadTime
	}
	if m.serverName != "" {
		warnlistSize.WithLabelValues(m.serverName).Set(float64(m.warnlist.Len()))
	}

}

// reverseString returns a reversed representation of the input, including unicode.
// Shamelessly taken from https://stackoverflow.com/a/34521190
func reverseString(s string) string {
	// It may be necessary to handle punycode in here at some point.
	size := len(s)
	buf := make([]byte, size)
	for start := 0; start < size; {
		r, n := utf8.DecodeRuneInString(s[start:])
		start += n
		utf8.EncodeRune(buf[size-start:], r)
	}
	return string(buf)
}

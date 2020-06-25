package malicious

import (
	"fmt"
	"strings"
	"time"

	"github.com/alecthomas/mph"
)

type Blacklist interface {
	Add(key string)
	Contains(key string) bool
	Close() error
	Len() int
	Open()
}

// type BlacklistBuilder interface {
// 	New(b Blacklist) Blacklist
// }

func NewBlacklist() Blacklist {
	b := &GoMapBlacklist{}
	b.Open()
	return b
}

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

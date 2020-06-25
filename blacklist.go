package malicious

import "github.com/alecthomas/mph"

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
	b := &MPHBlacklist{}
	b.Open()
	return b
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

	m.blacklist = blacklist

	return err
}

func (m *MPHBlacklist) Len() int {
	return m.blacklist.Len()
}

func (m *MPHBlacklist) Open() {
	m.builder = mph.Builder()
}

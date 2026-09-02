package warnlist

import (
	"context"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestServeDNSCountsWarnlistedHits(t *testing.T) {
	wl := NewWarnlist()
	wl.Add("example.org.")
	if err := wl.Close(); err != nil {
		t.Fatalf("closing warnlist: %v", err)
	}
	wp := WarnlistPlugin{Next: test.ErrorHandler(), warnlist: wl}

	// test.ResponseWriter always reports the client as 10.240.0.1; the server
	// label is empty because the context carries no server key.
	counter := warnlistCount.WithLabelValues("", "10.240.0.1", "example.org.")
	before := testutil.ToFloat64(counter)

	for _, q := range []string{"example.org.", "example.net."} {
		r := new(dns.Msg)
		r.SetQuestion(q, dns.TypeA)
		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		if _, err := wp.ServeDNS(context.TODO(), rec, r); err != nil {
			t.Fatalf("ServeDNS(%s): %v", q, err)
		}
	}

	if got := testutil.ToFloat64(counter) - before; got != 1 {
		t.Errorf("expected exactly one warnlist hit for example.org., got %v", got)
	}
	if got := testutil.ToFloat64(warnlistSize.WithLabelValues("")); got != 1 {
		t.Errorf("expected warnlist size gauge 1, got %v", got)
	}
}

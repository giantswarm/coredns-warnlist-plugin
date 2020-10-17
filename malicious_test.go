package malicious

import (
	"bytes"
	"context"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

func TestMalicious(t *testing.T) {
	// Create a new Malicious Plugin. Use the test.ErrorHandler as the next plugin.
	x := Malicious{Next: test.ErrorHandler()}

	// Setup a new output buffer that is *not* standard output, so we can check if
	// example is really being printed.
	b := &bytes.Buffer{}
	out = b

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("example.org.", dns.TypeA)
	// Create a new Recorder that captures the result, this isn't actually used in this test
	// as it just serves as something that implements the dns.ResponseWriter interface.
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	// Call our plugin directly, and check the result.
	_, err := x.ServeDNS(ctx, rec, r)
	if err != nil {
		t.Fatalf("Error serving DNS: %v", err)
	}
	if a := b.String(); a != "example\n" {
		t.Errorf("Failed to print '%s', got %s", "example", a)
	}
}

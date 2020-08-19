package malicious

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/coredns/coredns/request"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/miekg/dns"
)

// Define log to be a logger with the plugin name in it. This way we can just use log.Info and
// friends to log.
var log = clog.NewWithPlugin("malicious")

// Malicious is a plugin which counts requests to blacklisted domains
type Malicious struct {
	Next           plugin.Handler
	blacklist      Blacklist
	lastReloadTime time.Time
	Options        PluginOptions
	serverName     string
	quit           chan bool
}

// ServeDNS implements the plugin.Handler interface. This method gets called when malicious is used
// in a Server.
func (m *Malicious) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {

	req := request.Request{W: w, Req: r}

	if m.blacklist != nil {
		// See if the requested domain is in the cache
		retrievalStart := time.Now()
		hit := m.blacklist.Contains(req.Name())

		// Record the duration for the query
		blacklistCheckDuration.WithLabelValues(metrics.WithServer(ctx)).Observe(time.Since(retrievalStart).Seconds())

		if hit {
			// Warn and increment the counter for the hit
			blacklistCount.WithLabelValues(metrics.WithServer(ctx), req.IP(), req.Name()).Inc()
			log.Warning("host ", req.IP(), " requested blacklisted domain: ", req.Name())
		}

		// Update the current blacklist size metric
		blacklistSize.WithLabelValues(metrics.WithServer(ctx)).Set(float64(m.blacklist.Len()))
	} else {
		log.Warning("no blacklist has been loaded")
		// Update the current blacklist size metric to 0
		blacklistSize.WithLabelValues(metrics.WithServer(ctx)).Set(float64(0))
	}

	// Update the server name from context if it has changed
	if metrics.WithServer(ctx) != m.serverName {
		m.serverName = metrics.WithServer(ctx)
	}

	// Wrap the response when it returns from the next plugin
	pw := NewResponsePrinter(w)

	// Call next plugin (if any).
	return plugin.NextOrFailure(m.Name(), m.Next, ctx, pw, r)
}

// Name implements the Handler interface.
func (m Malicious) Name() string { return "malicious" }

// ResponsePrinter wraps a dns.ResponseWriter and will let the plugin inspect the response.
type ResponsePrinter struct {
	dns.ResponseWriter
}

// NewResponsePrinter returns ResponseWriter.
func NewResponsePrinter(w dns.ResponseWriter) *ResponsePrinter {
	return &ResponsePrinter{ResponseWriter: w}
}

// WriteMsg calls the underlying ResponseWriter's WriteMsg method and handles our future response logic.
func (r *ResponsePrinter) WriteMsg(res *dns.Msg) error {
	return r.ResponseWriter.WriteMsg(res)
}

// Make out a reference to os.Stdout so we can easily overwrite it for testing.
var out io.Writer = os.Stdout

package warnlist

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
var log = clog.NewWithPlugin("warnlist")

// WarnlistPlugin is a plugin which counts requests to warnlisted domains
type WarnlistPlugin struct {
	Next           plugin.Handler
	warnlist       Warnlist
	lastReloadTime time.Time
	Options        PluginOptions
	serverName     string
	quit           chan bool
}

// ServeDNS implements the plugin.Handler interface. This method gets called when warnlist is used
// in a Server.
func (wp *WarnlistPlugin) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {

	req := request.Request{W: w, Req: r}

	if wp.warnlist != nil {
		// See if the requested domain is in the cache
		retrievalStart := time.Now()
		hit := wp.warnlist.Contains(req.Name())

		// Record the duration for the query
		warnlistCheckDuration.WithLabelValues(metrics.WithServer(ctx)).Observe(time.Since(retrievalStart).Seconds())

		if hit {
			// Warn and increment the counter for the hit
			warnlistCount.WithLabelValues(metrics.WithServer(ctx), req.IP(), req.Name()).Inc()
			log.Warning("host ", req.IP(), " requested warnlisted domain: ", req.Name())
		}

		// Update the current warnlist size metric
		warnlistSize.WithLabelValues(metrics.WithServer(ctx)).Set(float64(wp.warnlist.Len()))
	} else {
		log.Warning("no warnlist has been loaded")
		// Update the current warnlist size metric to 0
		warnlistSize.WithLabelValues(metrics.WithServer(ctx)).Set(float64(0))
	}

	// Update the server name from context if it has changed
	if metrics.WithServer(ctx) != wp.serverName {
		wp.serverName = metrics.WithServer(ctx)
	}

	// Wrap the response when it returns from the next plugin
	pw := NewResponsePrinter(w)

	// Call next plugin (if any).
	return plugin.NextOrFailure(wp.Name(), wp.Next, ctx, pw, r)
}

// Name implements the Handler interface.
func (wp WarnlistPlugin) Name() string { return "warnlist" }

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
var out io.Writer = os.Stdout // nolint: unused

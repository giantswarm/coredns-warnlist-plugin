package example

import (
	"fmt"
	"time"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"

	"github.com/alecthomas/mph"
	"github.com/caddyserver/caddy"
)

// init registers this plugin.
func init() { plugin.Register("example", setup) }

// setup is the function that gets called when the config parser see the token "example". Setup is responsible
// for parsing any extra options the example plugin may have. The first token this function sees is "example".
func setup(c *caddy.Controller) error {
	c.Next() // Ignore "example" and give us the next token.
	if c.NextArg() {
		// If there was another token, return an error, because we don't have any configuration.
		// Any errors returned from this setup function should be wrapped with plugin.Error, so we
		// can present a slightly nicer error message to the user.
		return plugin.Error("example", c.ArgErr())
	}

	// Build the cache for the blacklist
	blacklist, err := buildCache()
	if err != nil {
		log.Error(err)
	}

	// Add a startup function that will -- after all plugins have been loaded -- check if the
	// prometheus plugin has been used - if so we will export metrics. We can only register
	// this metric once, hence the "once.Do".
	c.OnStartup(func() error {
		once.Do(func() { metrics.MustRegister(c, requestCount) })
		return nil
	})

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return Example{Next: next, blacklist: blacklist}
	})

	// All OK, return a nil error.
	return nil
}

func buildCache() (*mph.CHD, error) {
	// TODO: Make this function take a config file and iterate through it

	// Print a log message with the time it took to build the cache
	defer logTime(time.Now(), "Building blacklist cache took %s")

	builder := mph.Builder()
	builder.Add([]byte("example.org."), []byte(""))
	blacklist, err := builder.Build()

	return blacklist, err
}

// Prints the elapsed time in the pre-formatted message
func logTime(since time.Time, msg string) {
	elapsed := time.Since(since)
	msg = fmt.Sprintf(msg, elapsed)
	log.Info(msg)
}

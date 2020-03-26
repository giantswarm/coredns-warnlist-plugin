package example

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"

	"github.com/alecthomas/mph"
	"github.com/caddyserver/caddy"
)

// PluginOptions stores the configuration options given in the corefile
type PluginOptions struct {
	DomainFileName string
	IPFileName     string
}

// init registers this plugin.
func init() { plugin.Register("example", setup) }

// setup is the function that gets called when the config parser see the token "example". Setup is responsible
// for parsing any extra options the example plugin may have. The first token this function sees is "example".
func setup(c *caddy.Controller) error {

	options, err := parseArguments(c)
	if err != nil {
		log.Error("Unable to parse arguments: ", err)
	}

	// Build the cache for the blacklist
	blacklist, err := buildCacheFromFile(options.DomainFileName)
	if err != nil {
		log.Error(err)
	}

	// Add a startup function that will -- after all plugins have been loaded -- check if the
	// prometheus plugin has been used - if so we will export metrics. We can only register
	// this metric once, hence the "once.Do".
	c.OnStartup(func() error {
		once.Do(func() {
			metrics.MustRegister(c, blacklistCount)
		})
		return nil
	})

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return Example{Next: next, blacklist: blacklist}
	})

	// All OK, return a nil error.
	return nil
}

func parseArguments(c *caddy.Controller) (PluginOptions, error) {
	c.Next() // 0th token is the name of this plugin.

	options := PluginOptions{}

	i := 1
	for c.Next() {
		switch i {
		case 1:
			log.Info("Using domain blacklist file: ", c.Val())
			options.DomainFileName = c.Val()
		case 2:
			log.Info("Using IP blacklist file: ", c.Val())
			options.IPFileName = c.Val()
		}
		i++
	}

	if options.DomainFileName == "" {
		log.Error("domain blacklist file is required")
		return options, plugin.Error("example", c.ArgErr())
	}

	return options, nil
}

func buildCacheFromFile(fileName string) (*mph.CHD, error) {
	// Print a log message with the time it took to build the cache
	defer logTime(time.Now(), "Building blacklist cache took %s")

	file, err := os.Open(fileName)
	if err != nil {
		log.Error(err)
	}
	defer file.Close()

	builder := mph.Builder()

	// Known issue: the number of items in the cache must not be a power of 2
	// Because... math. So no files with only 2 entries. Or 4. Or 8... etc.
	// TODO: Get around this. Replace mph with custom hash set? Add a safe dummy blacklist item?
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := scanner.Text()
		// Assume all domains are global origin, with trailing dot (e.g. example.com.)
		if !strings.HasSuffix(domain, ".") {
			domain += "."
		}
		log.Info("Adding ", domain, " to domain blacklist")
		builder.Add([]byte(domain), []byte(""))
	}

	if err := scanner.Err(); err != nil {
		log.Error(err)
	}

	blacklist, err := builder.Build()

	return blacklist, err
}

// Prints the elapsed time in the pre-formatted message
func logTime(since time.Time, msg string) {
	elapsed := time.Since(since)
	msg = fmt.Sprintf(msg, elapsed)
	log.Info(msg)
}

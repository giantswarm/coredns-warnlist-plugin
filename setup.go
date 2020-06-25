package malicious

import (
	"fmt"
	"strings"
	"time"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"

	"github.com/caddyserver/caddy"
)

// PluginOptions stores the configuration options given in the corefile
type PluginOptions struct {
	// DomainFileName string
	// DomainURL string
	DomainSource     string
	DomainSourceType string
	FileFormat       string
	ReloadPeriod     time.Duration
}

// init registers this plugin.
func init() { plugin.Register("malicious", setup) }

// setup is the function that gets called when the config parser sees the token "malicious". Setup is responsible
// for parsing any extra options the plugin may have. The first token this function sees is "malicious".
func setup(c *caddy.Controller) error {

	options, err := parseArguments(c)
	if err != nil {
		log.Error("Unable to parse arguments: ", err)
		return err
	}

	// Build the cache for the blacklist
	blacklist, err := buildCacheFromFile(options)
	reloadTime := time.Now()
	if err != nil {
		if strings.Contains(err.Error(), "failed to find a collision-free hash function") {
			// Special case where there are 2^n objects in the mph blacklist
			log.Error("error building blacklist: number of items must not be a power of 2 (sorry)")
		} else {
			log.Error("error building blacklist: ", err)
		}
		reloadTime = time.Time{} // Time zero date
	}

	// TODO: Make reload async
	// e := Malicious{blacklist: blacklist, lastReloadTime: time.Now(), quit: make(chan bool)}
	// reloadHook(&e)

	// Add a startup function that will -- after all plugins have been loaded -- check if the
	// prometheus plugin has been used - if so we will export metrics. We can only register
	// this metric once, hence the "once.Do".
	c.OnStartup(func() error {
		once.Do(func() {
			metrics.MustRegister(c, blacklistCount)
			metrics.MustRegister(c, reloadsFailedCount)
			metrics.MustRegister(c, blacklistCheckDuration)
			metrics.MustRegister(c, blacklistSize)
		})
		return nil
	})

	// c.OnFinalShutdown(func() error {
	// 	e.quit <- true
	// 	return nil
	// })

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return &Malicious{Next: next, blacklist: blacklist, lastReloadTime: reloadTime, Options: options}
	})

	// All OK, return a nil error.
	return nil
}

func parseArguments(c *caddy.Controller) (PluginOptions, error) {
	c.Next() // 0th token is the name of this plugin

	options := PluginOptions{}

	for c.NextBlock() {
		if err := parseBlock(c, &options); err != nil {
			return options, err
		}
	}

	// Check that a source for the blacklist was given
	if options.DomainSource == "" {
		log.Error("domain blacklist file or url is required")
		return options, plugin.Error("malicious", c.ArgErr())
	}

	// Check that the specified file format is valid
	valid := false
	for _, t := range []string{DomainFileFormatHostfile, DomainFileFormatTextList} {
		if options.FileFormat == t {
			valid = true
		}
	}
	if !valid {
		return options, plugin.Error("malicious", c.Errf("unknown file format: %s", options.FileFormat))
	}

	return options, nil
}

func parseBlock(c *caddy.Controller, options *PluginOptions) error {
	switch c.Val() {
	case "file":
		if !c.NextArg() {
			return c.ArgErr()
		}
		options.DomainSource = c.Val()
		options.DomainSourceType = DomainSourceTypeFile
		if !c.NextArg() {
			return c.ArgErr()
		}
		options.FileFormat = c.Val()
		log.Infof("Using domain blacklist file: %s with format %s", options.DomainSource, options.FileFormat)

	case "url":
		if !c.NextArg() {
			return c.ArgErr()
		}
		if options.DomainSource != "" {
			return c.Err("file argument was already specified. Plugin can use either 'file' or 'url' option, but not both")
		}
		options.DomainSource = c.Val()
		options.DomainSourceType = DomainSourceTypeURL
		if !c.NextArg() {
			return c.ArgErr()
		}
		options.FileFormat = c.Val()
		log.Infof("Using domain blacklist url: %s with format %s", options.DomainSource, options.FileFormat)

	case "reload":
		if !c.NextArg() {
			return c.ArgErr()
		}

		t, err := time.ParseDuration(c.Val())
		if err != nil {
			log.Error("unable to parse reload duration")
			return c.ArgErr()
		}
		options.ReloadPeriod = t
		log.Infof("Using reload period of: %s", options.ReloadPeriod)
	}

	return nil
}

func buildCacheFromFile(options PluginOptions) (Blacklist, error) {
	// Print a log message with the time it took to build the cache
	defer logTime("Building blacklist cache took %s", time.Now())

	blacklist := NewBlacklist()
	for domain := range domainsGenerator(options.DomainSource, options.DomainSourceType, options.FileFormat) {
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

// TODO: Make reload asynchronous
// func reloadHook(e *Malicious) {
// 	go func() {
// 		tick := time.NewTicker(time.Second * 5)
// 		count := 0
// 		for {
// 			select {
// 			case <-e.quit:
// 				log.Info("Stopping hook")
// 				return

// 			case <-tick.C:
// 				log.Info("Hook ticked")
// 				count++
// 				if count > 5 {
// 					e.quit <- true
// 					break
// 				}
// 			}
// 		}
// 	}()
// }

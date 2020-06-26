package malicious

import (
	"time"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"

	"github.com/caddyserver/caddy"
)

// PluginOptions stores the configuration options given in the corefile
type PluginOptions struct {
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
		// Require the first build to succeed
		return err
	}

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
	q := make(chan bool)
	m := Malicious{blacklist: blacklist, lastReloadTime: reloadTime, Options: options, quit: q}

	tick := time.NewTicker(time.Second * 30)
	reloadHook(&m, tick)

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		m.Next = next
		return &m
	})

	// All OK, return a nil error.
	return nil
}

func reloadHook(e *Malicious, tick *time.Ticker) { //, quit chan bool) {
	log.Info("reload called")
	//quit := e.quit
	// defer close(e.quit)
	// defer tick.Stop()
	go func() {
		// tick := time.NewTicker(time.Second * 5)
		// defer tick.Stop()
		log.Info("func called")
		count := 0
		for {
			log.Info("loop iteration")
			select {
			case <-tick.C:
				log.Info("Hook ticked")

				count++
				if count > 2 {
					log.Info("Sending quit to hook")
					e.quit <- true
					// break
				}

				// Rebuild the cache for the blacklist
				blacklist, err := buildCacheFromFile(e.Options)
				if err != nil {
					log.Errorf("error rebuilding blacklist: %v#", err)
					// reloadsFailedCount.WithLabelValues(metrics.WithServer(ctx)).Inc()
					// Don't update the existing blacklist
				} else {
					reloadTime := time.Now()
					e.blacklist = blacklist
					e.lastReloadTime = reloadTime
				}

				// blacklistSize.WithLabelValues(metrics.WithServer(ctx)).Set(float64(e.blacklist.Len()))

			case <-e.quit:
				log.Info("Stopping hook")
				return
			}
		}
	}()
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

// Parses the configuration lines following our plugin declaration in the Corefile
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

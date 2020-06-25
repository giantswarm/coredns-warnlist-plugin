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
	DomainFileName string
	IPFileName     string
	ReloadPeriod   time.Duration
}

// init registers this plugin.
func init() { plugin.Register("malicious", setup) }

// setup is the function that gets called when the config parser sees the token "malicious". Setup is responsible
// for parsing any extra options the plugin may have. The first token this function sees is "malicious".
func setup(c *caddy.Controller) error {

	options, err := parseArguments(c)
	if err != nil {
		log.Error("Unable to parse arguments: ", err)
	}

	// Build the cache for the blacklist
	blacklist, err := buildCacheFromFile(options.DomainFileName)
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

	i := 1
	for c.Next() {
		switch i {
		case 1:
			// 1st token is domain blacklist file
			log.Info("Using domain blacklist file: ", c.Val())
			options.DomainFileName = c.Val()
		case 2:
			// 2nd token is IP blacklist file
			log.Info("Using IP blacklist file: ", c.Val())
			options.IPFileName = c.Val()
		case 3:
			// 3rd token is reload time
			t, err := time.ParseDuration(c.Val())
			if err != nil {
				log.Error("unable to parse reload duration")
			} else {
				log.Info("Setting reload time to: ", c.Val())
				options.ReloadPeriod = t
			}
		}
		i++
	}

	if options.DomainFileName == "" {
		log.Error("domain blacklist file is required")
		return options, plugin.Error("malicious", c.ArgErr())
	}

	return options, nil
}

func buildCacheFromFile(fileName string) (Blacklist, error) {
	// Print a log message with the time it took to build the cache
	defer logTime("Building blacklist cache took %s", time.Now())

	blacklist := NewBlacklist()
	for domain := range domainsGenerator(fileName, DomainSourceTypeFile, DomainFileFormatHostfile) {
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

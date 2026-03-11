package main

import (
	"fmt"
	"os"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/coremain"

	_ "github.com/coredns/coredns/core/plugin"

	_ "github.com/giantswarm/coredns-warnlist-plugin"
	"github.com/giantswarm/coredns-warnlist-plugin/pkg/project"
)

func init() {

	var newDirectives []string
	var addedWarnlist bool = false

	for _, plugin := range dnsserver.Directives {
		newDirectives = append(newDirectives, plugin)

		if plugin == "log" {
			if !addedWarnlist {
				newDirectives = append(newDirectives, "warnlist")
				addedWarnlist = true
			}
		}
	}

	if !addedWarnlist {
		fmt.Fprintln(os.Stderr, "Error: could not find 'log' plugin in CoreDNS directives")
		os.Exit(1)
	}

	dnsserver.Directives = newDirectives
}

func main() {
	// Add plugin version information to the CoreDNS version.
	caddy.AppVersion = fmt.Sprintf("%s+warnlist-%s", coremain.CoreVersion, project.Version())
	coremain.Run()
}

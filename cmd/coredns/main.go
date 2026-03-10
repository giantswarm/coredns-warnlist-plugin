package main

import (
	"fmt"
	"os"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/coremain"

	_ "github.com/coredns/coredns/core/plugin"
	_ "github.com/giantswarm/coredns-warnlist-plugin"
)

func main() {
	var logIdx int = -1
	for i, d := range dnsserver.Directives {
		if d == "log" {
			logIdx = i
			break
		}
	}

	if logIdx == -1 {
		fmt.Fprintln(os.Stderr, "Error: could not find 'log' plugin in CoreDNS directives")
		os.Exit(1)
	}

	var newDirectives []string
	newDirectives = append(newDirectives, dnsserver.Directives[:logIdx+1]...)
	newDirectives = append(newDirectives, "warnlist")
	newDirectives = append(newDirectives, dnsserver.Directives[logIdx+1:]...)

	dnsserver.Directives = newDirectives

	coremain.Run()
}

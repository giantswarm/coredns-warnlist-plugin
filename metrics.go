package example

import (
	"sync"

	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
)

var blacklistCount = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: "malicious_domain",
	Name:      "malicious_domains_request_total",
	Help:      "Counter of the number of requests made to blacklisted domains.",
}, []string{"server", "requestor", "domain"})

var once sync.Once

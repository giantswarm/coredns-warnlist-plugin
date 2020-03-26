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

var reloadsFailedCount = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: "malicious_domain",
	Name:      "malicious_domain_failed_reloads_count",
	Help:      "Counter of the number of times the plugin has failed to reload its blacklist.",
}, []string{"server"})

var once sync.Once

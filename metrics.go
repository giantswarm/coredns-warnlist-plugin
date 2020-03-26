package example

import (
	"sync"

	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
)

// requestCount exports a prometheus metric that is incremented every time a query is seen by the example plugin.
var requestCount = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: "example",
	Name:      "request_count_total",
	Help:      "Counter of requests made.",
}, []string{"server"})

var blacklistCount = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: "malicious_domain",
	Name:      "malicious_domains_request_total",
	Help:      "Counter of the number of requests made to blacklisted domains.",
}, []string{"server"})

var once sync.Once

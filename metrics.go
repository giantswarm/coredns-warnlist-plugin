package malicious

import (
	"sync"

	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
)

var blacklistCount = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: "malicious_domain",
	Name:      "malicious_domains_hits_total",
	Help:      "Counter of the number of requests made to blacklisted domains.",
}, []string{"server", "requestor", "domain"})

var blacklistCheckDuration = prometheus.NewSummaryVec(prometheus.SummaryOpts{
	Namespace: plugin.Namespace,
	Subsystem: "malicious_domain",
	Name:      "malicious_domains_cache_check_duration_seconds",
	Help:      "Summary of the average duration required to check the cache for a blacklisted domain.",
}, []string{"server"})

var blacklistSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: plugin.Namespace,
	Subsystem: "malicious_domain",
	Name:      "malicious_domains_blacklisted_items_count",
	Help:      "Counter of the number of currently blacklisted items.",
}, []string{"server"})

var reloadsFailedCount = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: "malicious_domain",
	Name:      "malicious_domains_failed_reloads_count",
	Help:      "Counter of the number of times the plugin has failed to reload its blacklist.",
}, []string{"server"})

var once sync.Once

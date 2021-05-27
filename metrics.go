package warnlist

import (
	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var warnlistCount = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: "malicious_domain",
	Name:      "malicious_domains_hits_total",
	Help:      "Counter of the number of requests made to warnlisted domains.",
}, []string{"server", "requestor", "domain"})

var warnlistCheckDuration = promauto.NewSummaryVec(prometheus.SummaryOpts{
	Namespace: plugin.Namespace,
	Subsystem: "malicious_domain",
	Name:      "malicious_domains_cache_check_duration_seconds",
	Help:      "Summary of the average duration required to check the cache for a warnlisted domain.",
}, []string{"server"})

var warnlistSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: plugin.Namespace,
	Subsystem: "malicious_domain",
	Name:      "malicious_domains_warnlisted_items_count",
	Help:      "Counter of the number of currently warnlisted items.",
}, []string{"server"})

var reloadsFailedCount = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: "malicious_domain",
	Name:      "malicious_domains_failed_reloads_count",
	Help:      "Counter of the number of times the plugin has failed to reload its warnlist.",
}, []string{"server"})

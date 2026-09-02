package warnlist

import (
	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// labelServer is the metric label carrying the CoreDNS server name.
const labelServer = "server"

var warnlistCount = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: pluginName,
	Name:      "warnlist_hits_total",
	Help:      "Counter of the number of requests made to warnlisted domains.",
}, []string{labelServer, "requestor", "domain"})

var warnlistCheckDuration = promauto.NewSummaryVec(prometheus.SummaryOpts{
	Namespace: plugin.Namespace,
	Subsystem: pluginName,
	Name:      "warnlist_cache_check_duration_seconds",
	Help:      "Summary of the average duration required to check the cache for a warnlisted domain.",
}, []string{labelServer})

var warnlistSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: plugin.Namespace,
	Subsystem: pluginName,
	Name:      "warnlist_warnlisted_items_count",
	Help:      "Counter of the number of currently warnlisted items.",
}, []string{labelServer})

var reloadsFailedCount = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: pluginName,
	Name:      "warnlist_failed_reloads_count",
	Help:      "Counter of the number of times the plugin has failed to reload its warnlist.",
}, []string{labelServer})

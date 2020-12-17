module github.com/giantswarm/coredns-malicious-domain-plugin

go 1.14

require (
	github.com/alecthomas/mph v0.0.0-20190930022807-712982e3d8a2
	github.com/alecthomas/unsafeslice v0.0.0-20190825002529-d95de1041e15 // indirect
	github.com/caddyserver/caddy v1.0.5
	github.com/coredns/coredns v1.7.1
	github.com/google/go-cmp v0.4.0
	github.com/miekg/dns v1.1.31
	github.com/prometheus/client_golang v1.9.0
)

replace github.com/gorilla/websocket v1.4.0 => github.com/gorilla/websocket v1.4.2

module github.com/giantswarm/coredns-malicious-domain-plugin

go 1.14

require (
	github.com/alecthomas/mph v0.0.0-20190930022807-712982e3d8a2
	github.com/alecthomas/unsafeslice v0.0.0-20190825002529-d95de1041e15 // indirect
	github.com/coredns/caddy v1.1.0
	github.com/coredns/coredns v1.8.3
	github.com/google/go-cmp v0.5.4
	github.com/hashicorp/go-immutable-radix v1.3.0
	github.com/miekg/dns v1.1.41
	github.com/prometheus/client_golang v1.10.0
)

replace github.com/gorilla/websocket v1.4.0 => github.com/gorilla/websocket v1.4.2

replace github.com/dgrijalva/jwt-go v3.2.0+incompatible => github.com/dgrijalva/jwt-go/v4 v4.0.0-preview1

replace github.com/gogo/protobuf v1.3.1 => github.com/gogo/protobuf v1.3.2

module github.com/giantswarm/coredns-warnlist-plugin

go 1.17

require (
	github.com/alecthomas/mph v0.0.0-20190930022807-712982e3d8a2
	github.com/coredns/caddy v1.1.1
	github.com/coredns/coredns v1.9.2
	github.com/google/go-cmp v0.5.8
	github.com/hashicorp/go-immutable-radix v1.3.1
	github.com/miekg/dns v1.1.49
	github.com/prometheus/client_golang v1.12.2
)

require (
	github.com/alecthomas/unsafeslice v0.0.0-20190825002529-d95de1041e15 // indirect
	github.com/apparentlymart/go-cidr v1.1.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/flynn/go-shlex v0.0.0-20150515145356-3f9db97f8568 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/grpc-ecosystem/grpc-opentracing v0.0.0-20180507213350-8e809c8a8645 // indirect
	github.com/hashicorp/go-uuid v1.0.2 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.34.0 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/stretchr/testify v1.7.1 // indirect
	golang.org/x/mod v0.4.2 // indirect
	golang.org/x/net v0.0.0-20220425223048-2871e0cb64e4 // indirect
	golang.org/x/sys v0.0.0-20220502124256-b6088ccd6cba // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/tools v0.1.6-0.20210726203631-07bc1bf47fb2 // indirect
	golang.org/x/xerrors v0.0.0-20220411194840-2f41105eb62f // indirect
	google.golang.org/genproto v0.0.0-20220429170224-98d788798c3e // indirect
	google.golang.org/grpc v1.46.0 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
)

replace github.com/gorilla/websocket v1.4.0 => github.com/gorilla/websocket v1.4.2

replace github.com/dgrijalva/jwt-go v3.2.0+incompatible => github.com/dgrijalva/jwt-go/v4 v4.0.0-preview1

replace github.com/gogo/protobuf v1.3.1 => github.com/gogo/protobuf v1.3.2

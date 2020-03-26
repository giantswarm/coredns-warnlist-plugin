# malicious-domain

## Name

*malicious-domain* - prints a log message and exposes a Prometheus metrics when blacklisted domains are requested.

## Description

This plugin accepts a domain blacklist file and prints an error if a blacklisted domain is requested.
It is planned to also expose a Prometheus metric with this information.

## File Format

The domain blacklist file should include one domain name per line.
Each is assumed to be a FQDN from the global origin (i.e. names are transformed to include a trailing `.` if one is not present).

There is currently a limitation in the underlying cache data structure that it cannot store a number of items which is a power of 2.
This means you must not provide a blacklist file with exactly 2, 4, 8, etc. items.

## Compilation

This package will always be compiled as part of CoreDNS and not in a standalone way. It will require you to use `go get` or as a dependency on [plugin.cfg](https://github.com/coredns/coredns/blob/master/plugin.cfg).

The [manual](https://coredns.io/manual/toc/#what-is-coredns) will have more information about how to configure and extend the server with external plugins.

A simple way to consume this plugin, is by adding the following on [plugin.cfg](https://github.com/coredns/coredns/blob/master/plugin.cfg), and recompile it as [detailed on coredns.io](https://coredns.io/2017/07/25/compile-time-enabling-or-disabling-plugins/#build-with-compile-time-configuration-file).

~~~
...
errors:errors
log:log
example:github.com/giantswarm/coredns-malicious-domain-plugin  # Add this line
dnstap:dnstap
acl:acl
...
~~~

After this you can compile coredns by:

```shell script
go generate
go build
```

Or you can instead use make:

```shell script
make
```

To compile using a local copy of the plugin, you can add a `replace` directive to `go.mod`:
```
replace github.com/giantswarm/coredns-malicious-domain-plugin => /path/to/go/src/github.com/giantswarm/coredns-malicious-domain-plugin
```

## Metrics

If monitoring is enabled (via the *prometheus* directive) the following metric is exported:

* `coredns_example_request_count_total{server}` - query count to the *example* plugin.

The `server` label indicated which server handled the request, see the *metrics* plugin for details.

## Ready

This plugin reports readiness to the ready plugin. It will be immediately ready.

## Examples

Sample corefile to show blacklist behavior

~~~ corefile
. {
    log
    whoami
    example domains.txt
}
~~~

## Also See

See the [manual](https://coredns.io/manual).

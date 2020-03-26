# malicious-domain

## Name

*malicious-domain* - prints a log message and exposes Prometheus metrics when blacklisted domains are requested.

## Description

This plugin accepts a domain blacklist file and prints an error if a blacklisted domain is requested.
It is planned to also expose a Prometheus metric with this information.

## Arguments

Sample Corefile line:
`example domains.txt ips.txt 5m`

Tokens:
`example` - the name of the plugin (for now)
`domains.txt` - the name of the file to load blacklisted domains
`ips.txt` - the name of the file to load blacklisted IPs (not currently used)
`5m` - a valid Go Duration after which the blacklist will be regenerated from the files

## File Format

The domain blacklist file should include one domain name per line.
Each is assumed to be a FQDN from the global origin (i.e. names are transformed to include a trailing `.` if one is not present).

There is currently a limitation in the underlying cache data structure that it cannot store a number of items which is a power of 2.
This means you must not provide a blacklist file with exactly 2, 4, 8, etc. items.

Sample:
```
example.org
somethingbad.biz
onlydanger.us
```

## Compilation

This plugin must be compiled with `coredns` -- it cannot be added to an existing `coredns` binary or Docker image.

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

If monitoring is enabled (via the *prometheus* directive) the following metrics are exported:

* `malicious_domains_request_total{server, requestor, domain}` - counts the number of blacklisted domains requested
* `malicious_domain_failed_reloads_count{server}` - counts the number of times the plugin has failed to reload its blacklist

The `server` label indicated which server handled the request.
The `requestor` label indicates the IP which requested the domain.
The `domain` label indicates the actual domain which was requested.
See the *metrics* plugin for more details.

By default, you can see the exported Prometheus metrics at `http://localhost:9153/metrics`

## Ready

This plugin reports readiness to the ready plugin. It will be immediately ready.

## Examples

Sample corefile

~~~ corefile
. {
    log
    # whoami
    example domains.txt ips.txt 5m
    prometheus
}
~~~

If running the server locally on port 1053, you can use
`dig +nocmd @localhost mx example.org -p1053 +noall +additional +tcp`
to send a request.
Using the domain blacklist above, this will trigger a blacklist hit.

## Also See

See the [manual](https://coredns.io/manual).

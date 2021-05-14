# malicious-domain

## Description

CoreDNS plugin which periodically updates a cache of malicious domains, and exposes metrics and logs when a prohibited domain is requested. It does not block the request.

**This project is under development and has not been tested for heavy production workloads.**

## Usage

We host a coredns image including this plugin at `quay.io/giantswarm/coredns-malicious-domain-plugin`. While we will try to keep this up to date on a best-effort basis, this is not an official image and may become behind or out of sync with the official image.

Alternatively, you can build an image yourself from the upstream codebase using the instructions in the **Compilation** section below.

## Arguments

The `malicious` plugin takes 4 arguments:

- the source type for the blacklist: either `url` or `file`
- the path to the source: either a url or file path
- the format of the file to expect: either `hostfile` or `text` (see below)
- the reload period: an optional Go Duration after which time (+/- 30% jitter) the blacklist will be regenerated*

\* when automatically reloading from a URL, please be friendly to the service hosting the file.

In your Corefile, the plugin options follow the format:

```
    malicious {
        <source type> <source path> <file format>
        reload <reload period>
    }
```

Sample Corefile configuration snippet (URL):
```
    malicious {
        url https://urlhaus.abuse.ch/downloads/hostfile/ hostfile
        reload 60m
    }
```

Sample Corefile configuration snippet (file):
```
    malicious {
        file domains.txt text
        reload 5m
    }
```

## File Format

The plugin can read files either as a list of individual domains (text mode) or in a hostfile format.
Both formats treat lines starting with `#` as comments and will disregard them.
Each domain is assumed to be a FQDN from the global origin (i.e. names are transformed to include a trailing `.` if one is not present).

In `text` mode, the domain file should include one domain name per line.

`text` Mode Sample:

```
example.org
somethingbad.biz
onlydanger.us
```

`hostfile` Mode Sample (from `abuse.ch`):

```
################################################################
# abuse.ch URLhaus Host file                                   #
# Last updated: 2020-06-24 14:05:05 (UTC)                      #
#                                                              #
# Terms Of Use: https://urlhaus.abuse.ch/api/                  #
# For questions please contact urlhaus [at] abuse.ch           #
################################################################
#
127.0.0.1	123evdenevenakliyat.com
127.0.0.1	1home.az
127.0.0.1	1sp1d.club
127.0.0.1	1sp2d.club
127.0.0.1	1sp3d.club
```

## Compilation

This plugin must be compiled with `coredns` -- it cannot be added to an existing `coredns` binary or Docker image.

A simple way to consume this plugin is by adding the following to [plugin.cfg](https://github.com/coredns/coredns/blob/master/plugin.cfg) and recompiling it as [detailed on coredns.io](https://coredns.io/2017/07/25/compile-time-enabling-or-disabling-plugins/#build-with-compile-time-configuration-file).

~~~
...
errors:errors
log:log
malicious:github.com/giantswarm/coredns-malicious-domain-plugin  # Add this line
dnstap:dnstap
acl:acl
...
~~~

Then you can compile coredns with:

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

You can then run `coredns` locally with `./coredns -dns.port "1053"`

## Metrics

If monitoring is enabled (via the *prometheus* directive) the following metrics are exported:

* `malicious_domains_hits_total{server, requestor, domain}` - counts the number of blacklisted domains requested
* `malicious_domains_failed_reloads_count{server}` - counts the number of times the plugin has failed to reload its blacklist
* `malicious_domains_cache_check_duration_seconds{server}` - summary exposing count and sum for determining the average time it takes to check the cache
* `malicious_domains_blacklisted_items_count{server}` - current number of domains stored in the blacklist

The `server` label indicated which server handled the request.

The `requestor` label indicates the IP which requested the domain.

The `domain` label indicates the actual domain which was requested.

See the *metrics* plugin for more details.

By default, you can see the exported Prometheus metrics at `http://localhost:9153/metrics` when `coredns` is running.

## Ready

This plugin reports readiness to the ready plugin. It will be immediately ready.

## Examples

Sample Corefile

~~~ corefile
. {
    log
    malicious {
        url https://urlhaus.abuse.ch/downloads/hostfile/ hostfile
        reload 5m
    }
    prometheus
    forward . /etc/resolv.conf
}
~~~

If running the server locally on port 1053, you can use
`dig +nocmd @localhost mx example.org -p1053 +noall +additional +tcp`
to send a request.
Using the domain blacklist above, this will trigger a blacklist hit.

## Also See

See the [manual](https://coredns.io/manual).

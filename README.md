# warnlist plugin

## Description

CoreDNS plugin which periodically updates a cache of domains, and exposes metrics and logs when a listed domain is requested. It does not block the request. This plugin is intended to facilitate low-noise alerting based on DNS requests for known malicious domains.

This plugin was previously referred to as `malicious-domains`.

**This project is under development and has not been tested for heavy production workloads.**

## Usage

We host a coredns image including this plugin at `quay.io/giantswarm/coredns-warnlist-plugin`. While we will try to keep this up to date on a best-effort basis, this is not an official image and may become behind or out of sync with the official image.

Alternatively, you can build an image yourself from the upstream codebase using the instructions in the **Compilation** section below.

## Arguments

The `warnlist` plugin takes the following arguments:

- the source type for the warnlist: either `url` or `file`
- the path to the source: either a url or file path
- the format of the file to expect: either `hostfile` or `text` (see below)
- the reload period: an optional Go Duration after which time (+/- 30% jitter) the warnlist will be regenerated*
- whether or not to match subdomains: `true` (default) or `false` (see [Subdomains](#subdomains))

\* when automatically reloading from a URL, please be friendly to the service hosting the file.

In your Corefile, the plugin options follow the format:

```
    warnlist {
        <source type> <source path> <file format>
        reload <reload period>
        match_subdomains <true | false>
    }
```

Sample Corefile configuration snippet (URL):
```
    warnlist {
        url https://urlhaus.abuse.ch/downloads/hostfile/ hostfile
        reload 60m
    }
```

Sample Corefile configuration snippet (file):
```
    warnlist {
        file domains.txt text
        reload 5m
        match_subdomains true
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

## Subdomains

This plugin can optionally check requests for subdomains of those explicitly listed on the warnlist. For example, using a warnlist containing `very.evil`, requesting `something.very.evil` would also trigger a match.

This feature (enabled by default) uses a [radix tree][iradix] to attempt to reduce the complexity of finding matches. This might affect the performance of the plugin more than the alternative Go map implementation (which can not match subdomains), but we don't yet have enough data to report how much impact can be expected.

## Compilation

This plugin must be compiled with `coredns` -- it cannot be added to an existing `coredns` binary or Docker image.

A simple way to consume this plugin is by adding the following to [plugin.cfg](https://github.com/coredns/coredns/blob/master/plugin.cfg) and recompiling it as [detailed on coredns.io](https://coredns.io/2017/07/25/compile-time-enabling-or-disabling-plugins/#build-with-compile-time-configuration-file).

~~~
...
errors:errors
log:log
warnlist:github.com/giantswarm/coredns-warnlist-plugin  # Add this line
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
replace github.com/giantswarm/coredns-warnlist-plugin => /path/to/go/src/github.com/giantswarm/coredns-warnlist-plugin
```

You can then run `coredns` locally with `./coredns -dns.port "1053"`

## Metrics

If monitoring is enabled (via the *prometheus* directive) the following metrics are exported:

* `warnlist_hits_total{server, requestor, domain}` - counts the number of warnlisted domains requested
* `warnlist_failed_reloads_count{server}` - counts the number of times the plugin has failed to reload its warnlist
* `warnlist_cache_check_duration_seconds{server}` - summary exposing count and sum for determining the average time it takes to check the cache
* `warnlist_warnlisted_items_count{server}` - current number of domains stored in the warnlist

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
    warnlist {
        url https://urlhaus.abuse.ch/downloads/hostfile/ hostfile
        reload 60m
    }
    prometheus
    forward . /etc/resolv.conf
}
~~~

If running the server locally on port 1053, you can use
`dig +nocmd @localhost mx example.org -p1053 +noall +additional +tcp`
to send a request.
Using the domain warnlist above, this will trigger a warnlist hit.

## Also See

See the [manual](https://coredns.io/manual).

[iradix]: https://github.com/hashicorp/go-immutable-radix/

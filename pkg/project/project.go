// Package project reports the plugin's own version, appended to the CoreDNS
// version string by cmd/coredns (e.g. "CoreDNS-1.14.7+warnlist-0.3.4").
//
// Two sources feed it, in order of precedence:
//
//  1. The value linked in at build time with
//     -ldflags "-X <module>/pkg/project.version=<value>". The generated
//     Makefile.gen.go.mk and the architect CI both pass this flag, so the
//     variable MUST stay a plain package-level string: the linker rejects -X
//     against anything else and the build fails.
//  2. The Go build info the toolchain embeds when the main package is built
//     inside its git checkout: the module version is the release tag
//     (v0.3.3), or a pseudo-version for a commit after a tag. A build without
//     VCS information (for example inside a Docker build context that excludes
//     .git) reports "(devel)", and this package then falls back to the short
//     revision, and finally to "unknown".
//
// Nothing here is hand-edited per release.
package project

import (
	"runtime/debug"
	"strings"
	"sync"
)

const unknownVersion = "unknown"

// version is set with -X at build time; empty for a plain `go build`.
var version string

var resolved = sync.OnceValue(func() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		bi = nil
	}
	return resolveVersion(version, bi)
})

// Version returns the plugin version without the leading "v".
func Version() string {
	return resolved()
}

func resolveVersion(linked string, bi *debug.BuildInfo) string {
	if v := strings.TrimSpace(linked); v != "" {
		return strings.TrimPrefix(v, "v")
	}
	return versionFromBuildInfo(bi)
}

func versionFromBuildInfo(bi *debug.BuildInfo) string {
	if bi == nil {
		return unknownVersion
	}

	if v := bi.Main.Version; v != "" && v != "(devel)" {
		return strings.TrimPrefix(v, "v")
	}

	var revision string
	modified := false
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if revision == "" {
		return unknownVersion
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if modified {
		return revision + "-dirty"
	}
	return revision
}

package project

import (
	"runtime/debug"
	"testing"
)

const (
	// taggedVersion is what a build at tag v0.3.3 resolves to.
	taggedVersion = "0.3.3"
	// develVersion is the module version Go reports when no VCS tag applies.
	develVersion = "(devel)"
)

func TestVersionFromBuildInfo(t *testing.T) {
	testCases := []struct {
		name string
		bi   *debug.BuildInfo
		want string
	}{
		{
			name: "nil build info",
			bi:   nil,
			want: unknownVersion,
		},
		{
			name: "tagged release build",
			bi:   &debug.BuildInfo{Main: debug.Module{Version: "v0.3.3"}},
			want: taggedVersion,
		},
		{
			name: "pseudo-version after a tag keeps the full pseudo-version",
			bi:   &debug.BuildInfo{Main: debug.Module{Version: "v0.3.4-0.20260902175430-b38f528c0f85"}},
			want: "0.3.4-0.20260902175430-b38f528c0f85",
		},
		{
			name: "devel build with vcs revision uses the short sha",
			bi: &debug.BuildInfo{
				Main: debug.Module{Version: develVersion},
				Settings: []debug.BuildSetting{
					{Key: "vcs.revision", Value: "b38f528c0f85a06fb97b54ccc3a717e3684f4684"},
					{Key: "vcs.modified", Value: "false"},
				},
			},
			want: "b38f528c0f85",
		},
		{
			name: "devel build with modified tree marks it dirty",
			bi: &debug.BuildInfo{
				Main: debug.Module{Version: develVersion},
				Settings: []debug.BuildSetting{
					{Key: "vcs.revision", Value: "b38f528c0f85a06fb97b54ccc3a717e3684f4684"},
					{Key: "vcs.modified", Value: "true"},
				},
			},
			want: "b38f528c0f85-dirty",
		},
		{
			name: "devel build without vcs info",
			bi:   &debug.BuildInfo{Main: debug.Module{Version: develVersion}},
			want: unknownVersion,
		},
		{
			name: "empty version",
			bi:   &debug.BuildInfo{},
			want: unknownVersion,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := versionFromBuildInfo(tc.bi); got != tc.want {
				t.Errorf("versionFromBuildInfo() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestResolveVersion covers the precedence between the value the build system
// links in with -X (generated Makefile, architect CI) and the Go build info
// fallback used by plain `go build`.
func TestResolveVersion(t *testing.T) {
	bi := &debug.BuildInfo{Main: debug.Module{Version: "v0.3.3"}}

	testCases := []struct {
		name   string
		linked string
		bi     *debug.BuildInfo
		want   string
	}{
		{name: "linked value wins over build info", linked: "0.3.6-dev.h675ed5f", bi: bi, want: "0.3.6-dev.h675ed5f"},
		{name: "linked value drops a leading v", linked: "v0.3.6", bi: bi, want: "0.3.6"},
		{name: "empty linked value falls back to build info", linked: "", bi: bi, want: taggedVersion},
		{name: "whitespace-only linked value falls back to build info", linked: "  ", bi: bi, want: taggedVersion},
		{name: "nothing known", linked: "", bi: nil, want: unknownVersion},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveVersion(tc.linked, tc.bi); got != tc.want {
				t.Errorf("resolveVersion(%q) = %q, want %q", tc.linked, got, tc.want)
			}
		})
	}
}

func TestVersionIsNeverEmpty(t *testing.T) {
	if Version() == "" {
		t.Fatal("Version() returned an empty string")
	}
}

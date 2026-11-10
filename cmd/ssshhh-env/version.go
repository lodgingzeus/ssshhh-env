package main

import "runtime/debug"

// version is set at release time with -ldflags "-X main.version=v1.2.3".
var version = "dev"

// versionString is the release version, or the module version for a
// `go install ...@version` build, or "dev".
func versionString() string {
	if version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return version
}

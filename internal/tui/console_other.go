//go:build !windows

package tui

// Enable turns on ANSI escape processing, which every terminal that is not a
// Windows console does already.
//
// The pair of files this belongs to is the only build tag in this repository.
// Everything else compiles unchanged for all four targets, which is how "works
// on my machine" is prevented here: by having almost no platform-specific code
// rather than by handling platform differences well.
func Enable() bool { return true }

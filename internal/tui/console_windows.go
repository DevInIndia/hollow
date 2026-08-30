//go:build windows

package tui

import (
	"os"
	"syscall"
)

// enableVirtualTerminalProcessing is the console mode bit that makes a Windows
// console interpret ANSI escape sequences instead of printing them. Windows
// Terminal sets it; the legacy console does not.
const enableVirtualTerminalProcessing = 0x0004

// syscall has the getter and not the setter, which is the whole reason this file
// exists. syscall.GetConsoleMode is declared in the standard library for Windows;
// syscall.SetConsoleMode is not, on any Go version this project supports, so the
// setter is reached through the DLL directly.
//
// The usual answer here is golang.org/x/sys/windows, which is not permitted, and
// LazyDLL is the standard library's own mechanism for exactly this. Lazy means
// the DLL is resolved at first call rather than at load, so a build for Windows
// that never draws a frame never touches kernel32.
var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

// Enable turns on ANSI escape processing for the console.
//
// It reports false when the mode cannot be set, and the caller then falls back
// to plain mode. Writing escape sequences into a console that will not interpret
// them fills the screen with garbage, which reads to a user as the program being
// broken rather than as the console being old.
func Enable() bool {
	h := syscall.Handle(os.Stdout.Fd())

	var mode uint32
	if err := syscall.GetConsoleMode(h, &mode); err != nil {
		// Not a console at all: a pipe or a file. Not an error, and not a
		// console to enable either.
		return false
	}
	if mode&enableVirtualTerminalProcessing != 0 {
		return true
	}

	// The return value is a BOOL, zero for failure. The error is deliberately
	// ignored: this call fails on a console that does not support the flag,
	// which is a supported configuration and not a fault to report.
	r, _, _ := procSetConsoleMode.Call(uintptr(h), uintptr(mode|enableVirtualTerminalProcessing))
	return r != 0
}

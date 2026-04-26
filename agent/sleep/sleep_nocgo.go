//go:build windows && amd64 && !cgo

package sleep

import "time"

// Sleep stubs for Windows builds without CGO (no C code available).
func EkkoSleep(duration time.Duration)        { time.Sleep(duration) }
func FoliageSleep(duration time.Duration)     { time.Sleep(duration) }
func FoliageSleepInline(duration time.Duration) { time.Sleep(duration) }

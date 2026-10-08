package config

import (
	"os"
	"time"
)

// SetWriteDelayForTest makes every config file write take at least d, to
// simulate a slow or spun-down disk. Pass 0 to restore normal behaviour.
// Test use only.
func SetWriteDelayForTest(d time.Duration) {
	if d == 0 {
		writeFileHook.Store(nil)
		return
	}
	f := func(name string, b []byte, perm os.FileMode) error {
		time.Sleep(d)
		return os.WriteFile(name, b, perm)
	}
	writeFileHook.Store(&f)
}

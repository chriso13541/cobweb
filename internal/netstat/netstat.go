// Package netstat reads interface link state and traffic counters directly
// from /sys/class/net, avoiding the need to shell out to `ip` for basic
// stats.
package netstat

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Interface holds a point-in-time snapshot of an interface's state and
// cumulative counters.
type Interface struct {
	Name      string
	Up        bool
	Carrier   bool // physical link detected (cable plugged in / associated)
	Speed     string
	RxBytes   uint64
	TxBytes   uint64
	Addr      string
}

const sysNetPath = "/sys/class/net"

// Stat reads current stats for a single named interface.
func Stat(name string) (Interface, error) {
	base := sysNetPath + "/" + name

	iface := Interface{Name: name}

	operstate, err := readTrimmed(base + "/operstate")
	if err != nil {
		return iface, fmt.Errorf("read operstate: %w", err)
	}
	iface.Up = operstate == "up"

	carrier, err := readTrimmed(base + "/carrier")
	iface.Carrier = err == nil && carrier == "1"

	speed, err := readTrimmed(base + "/speed")
	if err == nil && speed != "" && speed != "-1" {
		iface.Speed = speed + " Mb/s"
	} else {
		iface.Speed = "n/a"
	}

	iface.RxBytes = readUint(base + "/statistics/rx_bytes")
	iface.TxBytes = readUint(base + "/statistics/tx_bytes")

	iface.Addr = readAddr(name)

	return iface, nil
}

func readTrimmed(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func readUint(path string) uint64 {
	s, err := readTrimmed(path)
	if err != nil {
		return 0
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// HumanBytes formats a byte count as a short human-readable string.
func HumanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

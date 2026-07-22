package netstat

import (
	"os"
	"strconv"
	"strings"
)

// ConntrackStats reads the kernel's current NAT connection-tracking
// table size and configured ceiling. This is the real "how much is
// actively flowing through this box right now" number - not something
// cobweb tracks itself, since the kernel already does this natively
// for every NAT'd connection.
func ConntrackStats() (count, max int, err error) {
	count, err = readProcInt("/proc/sys/net/netfilter/nf_conntrack_count")
	if err != nil {
		return 0, 0, err
	}
	max, err = readProcInt("/proc/sys/net/netfilter/nf_conntrack_max")
	if err != nil {
		return count, 0, err
	}
	return count, max, nil
}

func readProcInt(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

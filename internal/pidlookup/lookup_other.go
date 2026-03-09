//go:build !darwin && !linux

package pidlookup

func lookupPort(port int) *ProcessInfo {
	return nil
}

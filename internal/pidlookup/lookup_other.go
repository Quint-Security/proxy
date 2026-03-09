//go:build !darwin && !linux

package pidlookup

func lookupPort(port int) *ProcessInfo {
	return nil
}

func lookupPortExcluding(port int, excludePID int) *ProcessInfo {
	return nil
}

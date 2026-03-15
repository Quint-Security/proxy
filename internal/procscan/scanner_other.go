//go:build !darwin && !linux

package procscan

func scanProcesses(selfPID int, sigs []AgentSignature) []AgentProcess {
	return nil
}

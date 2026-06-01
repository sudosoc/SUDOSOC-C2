//go:build !windows

package persistence

// WMISubscription stubs for non-Windows builds.
type WMISubscription struct {
	FilterName   string
	ConsumerName string
	Trigger      WMITrigger
	Payload      WMIPayload
	Namespace    string
}

type WMITrigger int
type WMIPayload struct {
	Command         string
	CommandArgs     string
	Script          string
	IntervalSeconds int
}

const (
	TriggerTimer  WMITrigger = iota
	TriggerLogon
	TriggerStartup
)

func DefaultSubscription(name, executablePath string) WMISubscription {
	return WMISubscription{}
}
func Install(_ WMISubscription) error              { return nil }
func Remove(_, _, _ string) error                  { return nil }
func List(_ string) (string, error)               { return "", nil }

package api

import "unifi-control/internal/common"

// ChannelStatusProvider defines the interface required by the API
type ChannelStatusProvider interface {
	GetPortIDs() []string
	GetPort(portID string) common.PortStatus
	Set(channel string, active bool) error
}

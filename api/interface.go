package api

import "hikvision-control/internal/common"

// ChannelStatusProvider defines the interface required by the API
type ChannelStatusProvider interface {
	GetChannels() []string
	GetChannel(channel string) common.ChannelStatus
	Set(channel string, active bool) error
}

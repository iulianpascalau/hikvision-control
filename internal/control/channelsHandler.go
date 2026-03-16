package control

import (
	"errors"
	"fmt"
	"regexp"

	"hikvision-control/internal/common"
	"hikvision-control/internal/config"

	"github.com/multiversx/mx-chain-core-go/core/check"
)

const unknownName = "unknown"

type channelsHandler struct {
	channelIDs    []string
	channelsAsMap map[string]config.ChannelConfig
	hikHandler    HikvisionHandler
}

func NewChannelsHandler(cfg config.Config, hikHandler HikvisionHandler) (*channelsHandler, error) {
	channelIDs, err := processChannels(cfg.Channels)
	if err != nil {
		return nil, err
	}

	if check.IfNilReflect(hikHandler) {
		return nil, errors.New("hikvision handler is nil")
	}

	return &channelsHandler{
		channelsAsMap: sliceToMap(cfg.Channels),
		channelIDs:    channelIDs,
		hikHandler:    hikHandler,
	}, nil
}

func processChannels(channels []config.ChannelConfig) ([]string, error) {
	m := make(map[string]int)

	channelIDs := make([]string, 0, len(channels))
	for _, ch := range channels {
		m[ch.Channel]++
		channelIDs = append(channelIDs, ch.Channel)
	}

	for ch, count := range m {
		if count > 1 {
			return nil, fmt.Errorf("channel %s was defined more than once", ch)
		}
	}

	return channelIDs, nil
}

func sliceToMap(channels []config.ChannelConfig) map[string]config.ChannelConfig {
	m := make(map[string]config.ChannelConfig)
	for _, ch := range channels {
		m[ch.Channel] = ch
	}

	return m
}

func (h *channelsHandler) GetChannels() []string {
	return h.channelIDs
}

func (h *channelsHandler) GetChannel(channel string) common.ChannelStatus {
	cfg, found := h.channelsAsMap[channel]
	if !found {
		return common.ChannelStatus{
			Channel: channel,
			Name:    unknownName,
			Error:   fmt.Sprintf("channel %s not found", channel),
		}
	}

	status := common.ChannelStatus{
		Name:    unknownName,
		Channel: cfg.Channel,
	}

	chanConfig, err := h.hikHandler.GetChannelConfig(channel)
	if err != nil {
		status.Error = err.Error()
		return status
	}

	// Parse the config and return the status (active: true if the IP address is set to the exact cfg.OkIPAddress, false otherwise)
	reIP := regexp.MustCompile(`<ipAddress>(.*?)</ipAddress>`)
	matches := reIP.FindSubmatch(chanConfig)
	status.Active = len(matches) > 1 && string(matches[1]) == cfg.OkIPAddress

	// Get the name of the channel from the received config
	reName := regexp.MustCompile(`<name>(.*?)</name>`)
	nameMatches := reName.FindSubmatch(chanConfig)
	if len(nameMatches) > 1 {
		status.Name = string(nameMatches[1])
	}

	return status
}

// Set updates the channel IP addresses on a specified channel with a provided bool value
func (h *channelsHandler) Set(channel string, active bool) error {
	cfg, found := h.channelsAsMap[channel]
	if !found {
		return fmt.Errorf("channel %s not found", channel)
	}

	chanConfig, err := h.hikHandler.GetChannelConfig(channel)
	if err != nil {
		return err
	}

	newIP := cfg.NOKIPAddress
	if active {
		newIP = cfg.OkIPAddress
	}

	reIP := regexp.MustCompile(`<ipAddress>.*?</ipAddress>`)
	newConfig := reIP.ReplaceAll(chanConfig, []byte(fmt.Sprintf("<ipAddress>%s</ipAddress>", newIP)))

	if string(newConfig) == string(chanConfig) {
		return errors.New("could not find <ipAddress> tag to replace")
	}

	return h.hikHandler.UpdateChannelConfig(channel, newConfig)
}

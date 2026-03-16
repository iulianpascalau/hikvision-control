package config

import (
	"testing"

	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/assert"
)

func TestConfig(t *testing.T) {
	t.Parallel()

	testString := `
[[Channels]]
    Channel = "0"
	OkIPAddress = "192.0.2.1"
	NokIPAddress = "192.1.2.1"

[[Channels]]
    Channel = "1"
	OkIPAddress = "192.0.2.2"
	NokIPAddress = "192.1.2.2"
`

	expectedCfg := Config{
		Channels: []ChannelConfig{
			{
				Channel:      "0",
				OkIPAddress:  "192.0.2.1",
				NOKIPAddress: "192.1.2.1",
			},
			{
				Channel:      "1",
				OkIPAddress:  "192.0.2.2",
				NOKIPAddress: "192.1.2.2",
			},
		},
	}

	cfg := Config{}

	err := toml.Unmarshal([]byte(testString), &cfg)
	assert.Nil(t, err)
	assert.Equal(t, expectedCfg, cfg)
}

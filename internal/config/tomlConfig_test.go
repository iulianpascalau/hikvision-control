package config

import (
	"testing"

	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/assert"
)

func TestConfig(t *testing.T) {
	t.Parallel()

	testString := `
ListenAddress = "0.0.0.0:8080"

[[Ports]]
	Name = "Camera 0"
    CameraMAC = "aa:bb:cc:dd:00:00"
	SwitchMAC = "aa:bb:cc:dd:ee:00"
	SwitchPort = 0

[[Ports]]
	Name = "Camera 1"
    CameraMAC = "aa:bb:cc:dd:00:01"
	SwitchMAC = "aa:bb:cc:dd:ee:01"
	SwitchPort = 1
`

	expectedCfg := Config{
		ListenAddress: "0.0.0.0:8080",
		Ports: []PortConfig{
			{
				Name:       "Camera 0",
				CameraMAC:  "aa:bb:cc:dd:00:00",
				SwitchMAC:  "aa:bb:cc:dd:ee:00",
				SwitchPort: 0,
			},
			{
				Name:       "Camera 1",
				CameraMAC:  "aa:bb:cc:dd:00:01",
				SwitchMAC:  "aa:bb:cc:dd:ee:01",
				SwitchPort: 1,
			},
		},
	}

	cfg := Config{}

	err := toml.Unmarshal([]byte(testString), &cfg)
	assert.Nil(t, err)
	assert.Equal(t, expectedCfg, cfg)
}

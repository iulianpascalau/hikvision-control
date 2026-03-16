package config

import (
	"fmt"
	"os"

	"github.com/pelletier/go-toml"
)

type ChannelConfig struct {
	Channel      string `toml:"Channel"`
	OkIPAddress  string `toml:"OkIPAddress"`
	NOKIPAddress string `toml:"NokIPAddress"`
}

type Config struct {
	Channels []ChannelConfig `toml:"Channels"`
}

// LoadConfig parses a TOML file into the Config struct
func LoadConfig(filepath string) (*Config, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file '%s': %w", filepath, err)
	}

	var cfg Config
	err = toml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to decode config file: %w", err)
	}

	return &cfg, nil
}

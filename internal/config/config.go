package config

import (
	"fmt"
	"os"

	"github.com/pelletier/go-toml"
)

type PortConfig struct {
	Name       string `toml:"Name"`
	CameraMAC  string `toml:"CameraMAC"` // Optional: If provided, SwitchMAC and SwitchPort will be discovered
	SwitchMAC  string `toml:"SwitchMAC"`
	SwitchPort int    `toml:"SwitchPort"`
}

type Config struct {
	ListenAddress string       `toml:"ListenAddress"`
	Ports         []PortConfig `toml:"Ports"`
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

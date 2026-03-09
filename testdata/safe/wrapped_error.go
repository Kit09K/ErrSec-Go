//go:build ignore

// Ground truth: NO ISSUE — errors wrapped with fmt.Errorf and returned.
package safe

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// LoadConfig reads and parses a JSON config file, properly propagating errors.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("LoadConfig: read: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("LoadConfig: parse: %w", err)
	}
	return &cfg, nil
}

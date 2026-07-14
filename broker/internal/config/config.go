// Package config loads the broker service configuration from YAML.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Service describes one advertised decoy service. The broker listens on
// ListenPort and forwards accepted connections to Backend.
type Service struct {
	// Name is a human friendly label, for example "ssh".
	Name string `yaml:"name"`
	// Enabled toggles the service on or off without removing config.
	Enabled bool `yaml:"enabled"`
	// ListenPort is the TCP port the broker binds on the public interface.
	ListenPort int `yaml:"listen_port"`
	// Backend is the "host:port" of the decoy container on the internal
	// network, for example "ssh-decoy:2222".
	Backend string `yaml:"backend"`
}

// Config is the top level broker configuration.
type Config struct {
	// Interface is the network interface the eBPF classifier attaches to,
	// typically "eth0" inside the broker container.
	Interface string `yaml:"interface"`
	// BPFObject is the path to the compiled eBPF object file.
	BPFObject string `yaml:"bpf_object"`
	// DialTimeoutSeconds bounds how long the broker waits when connecting
	// to a decoy backend.
	DialTimeoutSeconds int `yaml:"dial_timeout_seconds"`
	// Services is the list of advertised decoys.
	Services []Service `yaml:"services"`
}

// Load reads and validates the config file at path.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.Interface == "" {
		cfg.Interface = "eth0"
	}
	if cfg.BPFObject == "" {
		cfg.BPFObject = "/opt/decoy/decoy.bpf.o"
	}
	if cfg.DialTimeoutSeconds == 0 {
		cfg.DialTimeoutSeconds = 5
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	if len(c.Services) == 0 {
		return fmt.Errorf("no services configured")
	}
	seen := map[int]bool{}
	for _, s := range c.Services {
		if !s.Enabled {
			continue
		}
		if s.Name == "" {
			return fmt.Errorf("service with empty name")
		}
		if s.ListenPort <= 0 || s.ListenPort > 65535 {
			return fmt.Errorf("service %s: invalid listen_port %d", s.Name, s.ListenPort)
		}
		if seen[s.ListenPort] {
			return fmt.Errorf("service %s: duplicate listen_port %d", s.Name, s.ListenPort)
		}
		seen[s.ListenPort] = true
		if s.Backend == "" {
			return fmt.Errorf("service %s: empty backend", s.Name)
		}
	}
	return nil
}

// EnabledServices returns only the services that are turned on.
func (c *Config) EnabledServices() []Service {
	out := make([]Service, 0, len(c.Services))
	for _, s := range c.Services {
		if s.Enabled {
			out = append(out, s)
		}
	}
	return out
}

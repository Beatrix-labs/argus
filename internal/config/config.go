package config

import (
	"os"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Global struct {
		AppName     string `yaml:"app_name"`
		Environment string `yaml:"environment"`
	} `yaml:"global"`

	LogSource struct {
		Path     string `yaml:"path"`
		RealTime bool   `yaml:"real_time"`
	} `yaml:"log_source"`

	Engine struct {
		Behavioral struct {
			ErrorThreshold int `yaml:"error_threshold"`
			WindowSeconds  int `yaml:"window_seconds"`
		} `yaml:"behavioral"`
	} `yaml:"engine"`

	Action struct {
		BanFile string `yaml:"ban_file"`
	} `yaml:"action"`
}

func LoadConfig(path string) (*Config, error) {
	config := &Config{}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	d := yaml.NewDecoder(file)
	if err := d.Decode(&config); err != nil {
		return nil, err
	}

	return config, nil
}

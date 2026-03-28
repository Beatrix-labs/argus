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
		Path           string `yaml:"path"`
		RealTime       bool   `yaml:"real_time"`
		CustomLogRegex string `yaml:"custom_log_regex"`
	} `yaml:"log_source"`

	Engine struct {
		Behavioral struct {
			ErrorThreshold int `yaml:"error_threshold"`
			WindowSeconds  int `yaml:"window_seconds"`
		} `yaml:"behavioral"`
		Scoring struct {
			Threshold      int      `yaml:"threshold"`
			WindowSeconds  int      `yaml:"window_seconds"`
			WeightSQLi     int      `yaml:"weight_sqli"`
			WeightBrute    int      `yaml:"weight_brute"`
			WeightPathTrav int      `yaml:"weight_path_trav"`
			ScoreFile      string   `yaml:"score_file"`
			Whitelist      []string `yaml:"whitelist"`
		} `yaml:"scoring"`
	} `yaml:"engine"`

	Action struct {
		BanFile     string `yaml:"ban_file"`
		DryRun      bool   `yaml:"dry_run"`
		TTLLevel1   int    `yaml:"ttl_level_1"` // in minutes
		TTLLevel2   int    `yaml:"ttl_level_2"` // in minutes
		UseIPTables bool   `yaml:"use_iptables"`
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

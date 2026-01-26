package main

import (
	"os"

	"github.com/BurntSushi/toml"
)

var (
	configLoaded bool
	configFile   *config
	configErr    error
)

type config struct {
	Paths pathsConfig `toml:"paths"`
	CA    caConfig    `toml:"ca"`
	Leaf  leafConfig  `toml:"leaf"`
	Trust trustConfig `toml:"trust"`
}

type pathsConfig struct {
	CAROOT  string `toml:"ca_root"`
	CERTDIR string `toml:"cert_dir"`
}

type caConfig struct {
	Name          string `toml:"organization"`
	CommonName    string `toml:"common_name"`
	OrgUnit       string `toml:"organizational_unit"`
	ValidityDays  int    `toml:"validity_days"`
	ValidityYears int    `toml:"validity_years"`
}

type leafConfig struct {
	ValidityDays int         `toml:"validity_days"`
	Org          string      `toml:"organization"`
	OrgUnit      string      `toml:"organizational_unit"`
	Server       leafProfile `toml:"server"`
	Client       leafProfile `toml:"client"`
}

type leafProfile struct {
	ValidityDays int      `toml:"validity_days"`
	KeyUsage     []string `toml:"key_usage"`
}

type trustConfig struct {
	Stores []string `toml:"stores"`
}

func initConfig(path string) error {
	if configLoaded {
		return configErr
	}
	configFile, configErr = readConfig(path)
	configLoaded = true
	return configErr
}

func getConfig() *config {
	if !configLoaded {
		_ = initConfig("")
	}
	return configFile
}

func readConfig(path string) (*config, error) {
	if path == "" {
		return &config{}, nil
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return &config{}, nil
		}
		return nil, err
	}

	var cfg config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

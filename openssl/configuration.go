package openssl

import (
	"fmt"

	"github.com/spf13/viper"
)

var (
	conf *Config
)

func getConfig(v *viper.Viper) *Config {
	if conf == nil {
		conf = &Config{}

		err := v.Unmarshal(conf)
		if err != nil {
			panic(fmt.Errorf("unable to decode config.  %w", err))
		}
	}

	return conf
}

type CertificateAuthority struct {
	Directory string `mapstructure:"dir"`
	Name      string `mapstructure:"name"`
	Contact   string `mapstructure:"contact"`
	DaysValid int    `mapstructure:"daysValid"`
}

type Config struct {
	DefaultCAKeyLength   int                  `mapstructure:"caKeyLength"`
	DefaultCertKeyLength int                  `mapstructure:"certKeyLength"`
	HashAlgorithm        string               `mapstructure:"hashAlgorithm"`
	Country              string               `mapstructure:"country"`
	State                string               `mapstructure:"state"`
	City                 string               `mapstructure:"city"`
	Org                  string               `mapstructure:"organization"`
	OrgUnit              string               `mapstructure:"organizationalUnit"`
	Domain               string               `mapstructure:"domain"`
	RootCaConfig         CertificateAuthority `mapstructure:"rootAuthority"`
	IntermediateCaConfig CertificateAuthority `mapstructure:"intermediateAuthority"`
}

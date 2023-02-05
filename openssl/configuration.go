package openssl

import (
	"fmt"

	"github.com/spf13/viper"
)

var (
	v    *viper.Viper
	conf *Config
)

func GetConfig() *Config {
	if conf == nil {
		conf = &Config{}
		v := viper.New()

		configure(v)
		err := v.Unmarshal(conf)
		if err != nil {
			panic(fmt.Errorf("unable to decode config.  %w", err))
		}
	}

	return conf
}

func configure(v *viper.Viper) {
	v.SetConfigName("authority")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("..")
	v.AddConfigPath("./config")
	v.AddConfigPath("../config")

	err := v.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("fatal error while reading config: %w", err))
	}
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

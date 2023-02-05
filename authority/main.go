package authority

import (
	"fmt"
	"github.com/scraswell/golangca/openssl"
	"github.com/spf13/viper"
)

var config = viper.New()

func init() {
	configure()
	openssl.Initialize(config, false)
}

func GetConfig() *viper.Viper {
	return config
}

func configure() {
	config.SetConfigName("authority")
	config.SetConfigType("yaml")
	config.AddConfigPath(".")
	config.AddConfigPath("..")
	config.AddConfigPath("./config")
	config.AddConfigPath("../config")
	config.AutomaticEnv()

	err := config.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("fatal error while reading config: %w", err))
	}
}

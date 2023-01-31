package main

import (
	"fmt"

	"github.com/scraswell/golangca/openssl"
	"github.com/spf13/viper"
)

var config = viper.New()

func main() {
	configure()

	openssl.Initialize(config)
	openssl.ShowRootCertificateDatabase(config)
	openssl.UpdateRootCertificateDatabase(config)
	openssl.GenerateRootCaCrl(config)
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

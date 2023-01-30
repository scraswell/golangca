package openssl

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/scraswell/golangca/openssl_assets"
	"github.com/spf13/viper"
)

func ShowRootCertificateDatabase(v *viper.Viper) {
	c := getConfig(v)
	if c == nil {
		panic("Config was nil.")
	}

	log.Println(listCertificates(c, true))
}

func ShowIntermediateCertificateDatabase(v *viper.Viper) {
	c := getConfig(v)
	if c == nil {
		panic("Config was nil.")
	}

	log.Println(listCertificates(c, false))
}

func Initialize(v *viper.Viper) {
	c := getConfig(v)
	if c == nil {
		panic("Config was nil.")
	}

	var caDir = [...]string{
		c.RootCaConfig.Directory,
		c.IntermediateCaConfig.Directory,
	}

	for _, dir := range caDir {
		var isRootCa bool
		var passphrase string

		if dir == c.RootCaConfig.Directory {
			isRootCa = true
			passphrase = c.RootCaConfig.Passphrase
		} else {
			isRootCa = false
			passphrase = c.IntermediateCaConfig.Passphrase
		}

		createDirectories(dir)
		createEmptyDatabase(dir)
		intializeSerialNumber(dir)
		writeOutConfig(c, isRootCa)
		GenerateEncryptedRsaKey(passphrase, getPrivateKeyPath(dir), c.DefaultCAKeyLength)
	}

	GenerateRootCACertificate(c)
	GenerateIntermediateCaCsr(c)
	SignCertificate(&SigningParams{
		OpensslConfig:         getConfigPath(c.RootCaConfig.Directory, c.OpenSslConfigFile),
		Policy:                IntermediateCAPolicy,
		DaysValid:             3650,
		HashAlgorithm:         c.HashAlgorithm,
		Passphrase:            c.RootCaConfig.Passphrase,
		CsrInputPath:          (getCsrPath(c.RootCaConfig.Directory) + "/" + IntCaCsr),
		CertificateOutputPath: (getCertOutputPath(c.RootCaConfig.Directory) + "/" + IntCaCert),
	})
}

func GenerateIntermediateCaCsr(c *Config) {
	GenerateCsr(
		c.Country,
		c.State,
		c.City,
		c.Org,
		c.OrgUnit,
		c.IntermediateCaConfig.Name,
		c.IntermediateCaConfig.Contact,
		c.HashAlgorithm,
		getPrivateKeyPath(c.IntermediateCaConfig.Directory),
		getConfigPath(c.IntermediateCaConfig.Directory, c.OpenSslConfigFile),
		(getCsrPath(c.RootCaConfig.Directory) + "/" + IntCaCsr),
		c.IntermediateCaConfig.Passphrase)
}

func writeOutConfig(c *Config, isRoot bool) {
	var configFileTemplate string
	var directory string
	if isRoot {
		configFileTemplate = RootCaConfig
		directory = c.RootCaConfig.Directory
	} else {
		configFileTemplate = IntCaConfig
		directory = c.IntermediateCaConfig.Directory
	}

	data, found := openssl_assets.FS.String(configFileTemplate)

	if !found {
		panic(fmt.Errorf("Config file not found (%s).", configFileTemplate))
	}

	var configReplacementMap = make(map[string]string)
	configReplacementMap["{{ root_ca.dir }}"] = c.RootCaConfig.Directory
	configReplacementMap["{{ int_ca.dir }}"] = c.IntermediateCaConfig.Directory
	configReplacementMap["{{ country }}"] = c.Country
	configReplacementMap["{{ state }}"] = c.State
	configReplacementMap["{{ city }}"] = c.City
	configReplacementMap["{{ org }}"] = c.Org
	configReplacementMap["{{ ou }}"] = c.OrgUnit
	configReplacementMap["{{ int_ca.crl }}"] = getCrlUrl(c.Domain, isRoot)

	for key, value := range configReplacementMap {
		data = strings.Replace(data, key, value, -1)
	}

	configFilePath := getConfigPath(directory, c.OpenSslConfigFile)
	configFile, err := os.Create(configFilePath)
	if err != nil {
		panic(fmt.Errorf("Error while creating configuration file (%s): %w", configFilePath, err))
	}

	configFile.WriteString(data)
	configFile.Close()

	log.Printf("Created CA configuration file: %s", configFilePath)
}

func intializeSerialNumber(path string) {
	serialFilePath := fmt.Sprintf("%s/%s", path, SerialNumberFile)

	serialFile, err := os.Create(serialFilePath)
	if err != nil {
		panic(fmt.Errorf("Error while creating serial number file (%s): %w", serialFilePath, err))
	}

	serialFile.WriteString(StartingSerialNumber)
	serialFile.Close()

	log.Printf("Created CA serial number file: %s", serialFilePath)
}

func createEmptyDatabase(path string) {
	dbFilePath := fmt.Sprintf("%s/%s", path, DbFileName)

	dbFile, err := os.Create(dbFilePath)
	if err != nil {
		panic(fmt.Errorf("Error while creating database file (%s): %w", dbFilePath, err))
	}
	dbFile.Close()

	log.Printf("Created CA database file: %s", dbFilePath)
}

func createDirectories(path string) {
	for _, d := range AuthorityDirs {
		dir := fmt.Sprintf("%s/%s", path, d)

		log.Printf("Creating directory: %s", dir)

		err := os.MkdirAll(dir, os.FileMode.Perm(0o700))
		if err != nil {
			panic(fmt.Errorf("Fatal error while reading config: %w", err))
		}
	}
}

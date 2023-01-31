package openssl

import (
	"log"

	"github.com/spf13/viper"
)

func init() {
	assertAvailablePRNG()
}

func GenerateRootCaCrl(v *viper.Viper) {
	generateCrl(readConfig(v), true)
}

func GenerateIntermediateCaCrl(v *viper.Viper) {
	generateCrl(readConfig(v), false)
}

func UpdateRootCertificateDatabase(v *viper.Viper) {
	updatedb(readConfig(v), true)
}

func UpdateIntermediateCertificateDatabase(v *viper.Viper) {
	updatedb(readConfig(v), false)
}

func ShowRootCertificateDatabase(v *viper.Viper) {
	log.Println(listCertificates(readConfig(v), true))
}

func ShowIntermediateCertificateDatabase(v *viper.Viper) {
	log.Println(listCertificates(readConfig(v), false))
}

func Initialize(v *viper.Viper) {
	c := readConfig(v)

	var caDir = [...]string{
		c.RootCaConfig.Directory,
		c.IntermediateCaConfig.Directory,
	}

	for _, dir := range caDir {
		var isRootCa bool

		if dir == c.RootCaConfig.Directory {
			isRootCa = true
		} else {
			isRootCa = false
		}

		createDirectories(dir)
		generatePassphraseFile(c, isRootCa)
		createEmptyDatabase(dir)
		intializeSerialNumber(dir)
		generateCrlNumberFile(c, isRootCa)
		writeOutConfig(c, isRootCa)

		GenerateEncryptedRsaKey(
			getPassphrase(c, isRootCa),
			getPrivateKeyPath(dir),
			c.DefaultCAKeyLength)
	}

	GenerateRootCACertificate(c)
	GenerateIntermediateCaCsr(c)
	SignCertificate(&SigningParams{
		OpensslConfig:         getConfigPath(c.RootCaConfig.Directory),
		Policy:                IntermediateCAPolicy,
		DaysValid:             c.IntermediateCaConfig.DaysValid,
		HashAlgorithm:         c.HashAlgorithm,
		Passphrase:            getPassphraseFilePath(c.RootCaConfig.Directory),
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
		getConfigPath(c.IntermediateCaConfig.Directory),
		(getCsrPath(c.RootCaConfig.Directory) + "/" + IntCaCsr),
		getPassphrase(c, false))
}

func readConfig(v *viper.Viper) *Config {
	c := getConfig(v)
	if c == nil {
		panic("Config was nil.")
	}

	return c
}

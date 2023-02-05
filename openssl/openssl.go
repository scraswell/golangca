package openssl

import (
	"fmt"
	"github.com/scraswell/golangca/openssl/common"
	"github.com/spf13/viper"
	"io"
	"log"
	"os"
)

func init() {
	common.AssertAvailablePRNG()
}

func GetRootCertificate(v *viper.Viper) string {
	return getRootCertificate(readConfig(v))
}

func GetCrlForRootCa(v *viper.Viper) string {
	return getCrl(readConfig(v), true)
}

func GetCrlForIntermediateCa(v *viper.Viper) string {
	return getCrl(readConfig(v), false)
}

func RevokeRootCaCertificate(v *viper.Viper, certificateSerialNumber string) {
	revokeCertificate(readConfig(v), true, certificateSerialNumber)
}

func RevokeIntermediateCaCertificate(v *viper.Viper, certificateSerialNumber string) {
	revokeCertificate(readConfig(v), false, certificateSerialNumber)
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

func ShowRootCertificateDatabase(v *viper.Viper) string {
	return listCertificates(readConfig(v), true)
}

func ShowIntermediateCertificateDatabase(v *viper.Viper) string {
	return listCertificates(readConfig(v), false)
}

func Initialize(v *viper.Viper, forceNew bool) {
	c := readConfig(v)

	if !isInitialized(c) || forceNew {
		initialize(c)
	}
}

func isInitialized(c *Config) bool {
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

		if fileExists(getCaCertificatePath(dir)) && fileExists(getPrivateKeyPath(dir)) && fileExists(getPassphraseFilePath(dir)) {
			TestKeyPassphrase(c, isRootCa)
		} else {
			log.Print("CA not previously initialized; initializing as new.")
			return false
		}
	}

	log.Print("CA already initialized.")
	return true
}

func initialize(c *Config) {
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

		deleteDirectory(dir)
		createDirectories(dir)
		generatePassphraseFile(c, isRootCa)
		createEmptyDatabase(dir)
		initializeSerialNumberFile(dir)
		generateCrlNumberFile(c, isRootCa)
		writeOutConfig(c, isRootCa)

		common.GenerateEncryptedRsaKey(
			getPassphrase(c, isRootCa),
			getPrivateKeyPath(dir),
			c.DefaultCAKeyLength)

		TestKeyPassphrase(c, isRootCa)
	}

	GenerateRootCACertificate(c)
	GenerateIntermediateCaCsr(c)

	output := getCertOutputPath(c.RootCaConfig.Directory) + "/" + IntCaCert
	SignCertificate(&SigningParams{
		OpensslConfig:         getConfigPath(c.RootCaConfig.Directory),
		Policy:                IntermediateCAPolicy,
		DaysValid:             c.IntermediateCaConfig.DaysValid,
		HashAlgorithm:         c.HashAlgorithm,
		Passphrase:            getPassphraseFilePath(c.RootCaConfig.Directory),
		CsrInputPath:          getCsrPath(c.RootCaConfig.Directory) + "/" + IntCaCsr,
		CertificateOutputPath: output,
	})

	CopySignedIntermediateCaCertificate(c.IntermediateCaConfig, output)
}

func CopySignedIntermediateCaCertificate(config CertificateAuthority, output string) {
	sourceFileStat, err := os.Stat(output)
	if err != nil {
		panic(fmt.Errorf("ca certificate did not exist %w", err))
	}

	if !sourceFileStat.Mode().IsRegular() {
		panic(fmt.Errorf("%s is not a regular file", output))
	}

	source, err := os.Open(output)
	if err != nil {
		panic(fmt.Errorf("failed to open %s", output))
	}
	defer source.Close()

	destination := createFile(getCaCertificatePath(config.Directory))
	defer destination.Close()

	_, err = io.Copy(destination, source)
	if err != nil {
		panic(fmt.Errorf("failed to copy %s", output))
	}
}

func GenerateIntermediateCaCsr(c *Config) {
	common.GenerateCsr(
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
		getCsrPath(c.RootCaConfig.Directory)+"/"+IntCaCsr,
		getPassphrase(c, false))
}

func readConfig(v *viper.Viper) *Config {
	c := getConfig(v)
	if c == nil {
		panic("Config was nil.")
	}

	return c
}

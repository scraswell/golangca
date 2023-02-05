package openssl

import (
	"fmt"
	"github.com/scraswell/golangca/openssl/common"
	"io"
	"log"
	"os"
)

func init() {
	common.AssertAvailablePRNG()
}

func Initialize(forceNew bool) {
	if !isInitialized() || forceNew {
		initialize()
	}
}

func isInitialized() bool {
	var c = GetConfig()

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
			TestKeyPassphrase(isRootCa)
		} else {
			log.Print("CA not previously initialized; initializing as new.")
			return false
		}
	}

	log.Print("CA already initialized.")
	return true
}

func initialize() {
	var c = GetConfig()

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
		generatePassphraseFile(isRootCa)
		createEmptyDatabase(dir)
		initializeSerialNumberFile(dir)
		generateCrlNumberFile(isRootCa)
		writeOutConfig(isRootCa)

		common.GenerateEncryptedRsaKey(
			getPassphrase(isRootCa),
			getPrivateKeyPath(dir),
			c.DefaultCAKeyLength)

		TestKeyPassphrase(isRootCa)
	}

	GenerateRootCACertificate()
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
	defer func(source *os.File) {
		err := source.Close()
		if err != nil {
			panic(fmt.Errorf("failed to close source file %w", err))
		}
	}(source)

	destination := createFile(getCaCertificatePath(config.Directory))
	defer func(destination *os.File) {
		err := destination.Close()
		if err != nil {
			panic(fmt.Errorf("failed to close destination file %w", err))
		}
	}(destination)

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
		getPassphrase(false))
}

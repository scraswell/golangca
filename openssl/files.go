package openssl

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/scraswell/golangca/openssl_assets"
)

func generatePassphraseFile(c *Config, isRoot bool) {
	var passphraseFilePath string
	if isRoot {
		passphraseFilePath = getPassphraseFilePath(c.RootCaConfig.Directory)
	} else {
		passphraseFilePath = getPassphraseFilePath(c.IntermediateCaConfig.Directory)
	}

	passphrase, err := GenerateRandomStringURLSafe(PassphraseLengthBytes)
	if err != nil {
		panic(fmt.Errorf("failed to generate passphrase: %w", err))
	}

	passphraseFile := createFile(passphraseFilePath)
	passphraseFile.WriteString(passphrase)
	passphraseFile.Close()
	protectFile(passphraseFilePath)
}

func getPassphrase(c *Config, isRoot bool) string {
	var passphraseFilePath string
	if isRoot {
		passphraseFilePath = getPassphraseFilePath(c.RootCaConfig.Directory)
	} else {
		passphraseFilePath = getPassphraseFilePath(c.IntermediateCaConfig.Directory)
	}

	fileBytes, err := os.ReadFile(passphraseFilePath)
	if err != nil {
		panic(fmt.Errorf("unable to read passphrase file: %w", err))
	}

	return string(fileBytes)
}

func generateCrlNumberFile(c *Config, isRoot bool) {
	var cadir string
	if isRoot {
		cadir = c.RootCaConfig.Directory
	} else {
		cadir = c.IntermediateCaConfig.Directory
	}

	CrlNumberFilePath := getCrlNumberPath(cadir)
	crlNumberFile := createFileWithContent(CrlNumberFilePath, StartingCrlNumber)
	crlNumberFile.Close()
	protectFile(CrlNumberFilePath)
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
		panic(fmt.Errorf("config file not found (%s)", configFileTemplate))
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
		data = strings.ReplaceAll(data, key, value)
	}

	configFilePath := getConfigPath(directory)
	configFile := createFileWithContent(configFilePath, data)
	configFile.Close()
	protectFile(configFilePath)

	log.Printf("Created CA configuration file: %s", configFilePath)
}

func intializeSerialNumber(path string) {
	serialFilePath := fmt.Sprintf("%s/%s", path, SerialNumberFile)

	serialFile := createFileWithContent(serialFilePath, StartingSerialNumber)
	serialFile.Close()
	protectFile(serialFilePath)

	log.Printf("Created CA serial number file: %s", serialFilePath)
}

func createEmptyDatabase(path string) {
	dbFilePath := fmt.Sprintf("%s/%s", path, DbFileName)

	dbFile := createFile(dbFilePath)
	dbFile.Close()
	protectFile(dbFilePath)

	log.Printf("Created CA database file: %s", dbFilePath)
}

func createDirectories(path string) {
	for _, d := range AuthorityDirs {
		dir := fmt.Sprintf("%s/%s", path, d)

		log.Printf("Creating directory: %s", dir)

		err := os.MkdirAll(dir, os.FileMode.Perm(0o700))
		if err != nil {
			panic(fmt.Errorf("fatal error while reading config: %w", err))
		}
	}
}

func createFile(filePath string) *os.File {
	file, err := os.Create(filePath)
	if err != nil {
		panic(fmt.Errorf("error creating file (%s): %w", filePath, err))
	}

	return file
}

func createFileWithContent(filePath string, content string) *os.File {
	file := createFile(filePath)

	_, err := file.WriteString(content)
	if err != nil {
		panic(fmt.Errorf("unable to write content to file (%s): %w", filePath, err))
	}

	return file
}

func protectFile(filePath string) {
	err := os.Chmod(filePath, os.FileMode.Perm(0o600))
	if err != nil {
		panic(fmt.Errorf("error changing the file mode (%s): %w", filePath, err))
	}
}

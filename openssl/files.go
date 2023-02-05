package openssl

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/scraswell/golangca/openssl/assets"
	"github.com/scraswell/golangca/openssl/common"
)

func generatePassphraseFile(c *Config, isRoot bool) {
	var passphraseFilePath string
	if isRoot {
		passphraseFilePath = getPassphraseFilePath(c.RootCaConfig.Directory)
	} else {
		passphraseFilePath = getPassphraseFilePath(c.IntermediateCaConfig.Directory)
	}

	passphrase, err := common.GenerateRandomStringURLSafe(PassphraseLengthBytes)
	if err != nil {
		panic(fmt.Errorf("failed to generate passphrase: %w", err))
	}

	passphraseFile := createFile(passphraseFilePath)
	writeContentToFile(passphrase, passphraseFile)
	closeFile(passphraseFile)
	common.ProtectFile(passphraseFilePath)
}

func getPassphrase(c *Config, isRoot bool) string {
	var passphraseFilePath string
	if isRoot {
		passphraseFilePath = getPassphraseFilePath(c.RootCaConfig.Directory)
	} else {
		passphraseFilePath = getPassphraseFilePath(c.IntermediateCaConfig.Directory)
	}

	return readStringFromFile(passphraseFilePath)
}

func getCrl(c *Config, isRoot bool) string {
	var crlFilePath string
	if isRoot {
		crlFilePath = getCrlPath(c.RootCaConfig.Directory)
	} else {
		crlFilePath = getCrlPath(c.IntermediateCaConfig.Directory)
	}

	return readStringFromFile(crlFilePath)
}

func generateCrlNumberFile(c *Config, isRoot bool) {
	var caDir string
	if isRoot {
		caDir = c.RootCaConfig.Directory
	} else {
		caDir = c.IntermediateCaConfig.Directory
	}

	CrlNumberFilePath := getCrlNumberPath(caDir)
	crlNumberFile := createFileWithContent(CrlNumberFilePath, StartingCrlNumber)
	closeFile(crlNumberFile)
	common.ProtectFile(CrlNumberFilePath)
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

	data, found := assets.FS.String(configFileTemplate)

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
	closeFile(configFile)
	common.ProtectFile(configFilePath)

	log.Printf("Created CA configuration file: %s", configFilePath)
}

func initializeSerialNumberFile(path string) {
	serialFilePath := fmt.Sprintf("%s/%s", path, SerialNumberFile)

	serialFile := createFileWithContent(serialFilePath, StartingSerialNumber)
	closeFile(serialFile)
	common.ProtectFile(serialFilePath)

	log.Printf("Created CA serial number file: %s", serialFilePath)
}

func readStringFromFile(filePath string) string {
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		panic(fmt.Errorf("unable to read file: %w", err))
	}

	return string(fileBytes)
}

func createEmptyDatabase(path string) {
	dbFilePath := fmt.Sprintf("%s/%s", path, DbFileName)

	dbFile := createFile(dbFilePath)
	closeFile(dbFile)
	common.ProtectFile(dbFilePath)

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

	writeContentToFile(content, file)
	return file
}

func writeContentToFile(line string, file *os.File) {
	_, err := file.WriteString(line)
	if err != nil {
		panic(fmt.Errorf("failed to write string to file. %w", err))
	}
}

func closeFile(file *os.File) {
	err := file.Close()
	if err != nil {
		panic(fmt.Errorf("failed to close file %w", err))
	}
}

func deleteDirectory(directory string) {
	log.Printf("deleting %s recursively...", directory)
	err := os.RemoveAll(directory)
	if err != nil {
		panic(fmt.Errorf("unable to remove directory %w", err))
	}
}

func fileExists(filePath string) bool {
	stat, err := os.Stat(filePath)

	if err == nil && stat.IsDir() {
		return false
	} else if err == nil {
		return true
	} else if err != nil && errors.Is(err, os.ErrNotExist) {
		return false
	} else {
		panic("stat call failed")
	}
}

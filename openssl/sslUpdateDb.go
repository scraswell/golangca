package openssl

import (
	"fmt"
	"log"
)

const updateDbConfigIndex = 2
const updateDbPassphraseIndex = 4

var updateDbArgs = [...]string{
	"ca",
	"-config",
	"%s",
	"-passin",
	"file:%s",
	"-updatedb",
}

func genUpdateDbArgs(c *Config, isRootCa bool) []string {
	var config string
	var passphraseFile string

	if isRootCa {
		config = getConfigPath(c.RootCaConfig.Directory, c.OpenSslConfigFile)
		passphraseFile = getPassphraseFilePath(c.RootCaConfig.Directory)
	} else {
		config = getConfigPath(c.IntermediateCaConfig.Directory, c.OpenSslConfigFile)
		passphraseFile = getPassphraseFilePath(c.IntermediateCaConfig.Directory)
	}

	var args []string

	for i, arg := range updateDbArgs {
		switch i {
		case updateDbConfigIndex:
			arg = fmt.Sprintf(arg, config)
		case updateDbPassphraseIndex:
			arg = fmt.Sprintf(arg, passphraseFile)
		}

		args = append(args, arg)
	}

	return args
}

func updatedb(c *Config, isRootCa bool) {
	log.Printf("Updating the certificate database.")
	exitCode, standardOutput, standardError := InvokeOpensslCommand(genUpdateDbArgs(c, isRootCa)...)

	if exitCode != 0 {
		panic(fmt.Sprintf(
			"openssl invocation returned non-zero exit code: %d\n\nStdOut:\n%s\nStdErr:\n%s\n",
			exitCode,
			standardOutput,
			standardError))
	}
}

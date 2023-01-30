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
	"pass:%s",
	"-updatedb",
}

func genUpdateDbArgs(c *Config, isRootCa bool) []string {
	var config string
	var passphrase string

	if isRootCa {
		config = getConfigPath(c.RootCaConfig.Directory, c.OpenSslConfigFile)
		passphrase = c.RootCaConfig.Passphrase
	} else {
		config = getConfigPath(c.IntermediateCaConfig.Directory, c.OpenSslConfigFile)
		passphrase = c.IntermediateCaConfig.Passphrase
	}

	var args []string

	for i, arg := range updateDbArgs {
		if i == updateDbConfigIndex {
			arg = fmt.Sprintf(arg, config)
		} else if i == updateDbPassphraseIndex {
			arg = fmt.Sprintf(arg, passphrase)
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

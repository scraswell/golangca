package openssl

import (
	"fmt"
	"log"

	"github.com/scraswell/golangca/openssl/common"
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
	var cadir string
	if isRootCa {
		cadir = c.RootCaConfig.Directory
	} else {
		cadir = c.IntermediateCaConfig.Directory
	}

	var args []string

	for i, arg := range updateDbArgs {
		switch i {
		case updateDbConfigIndex:
			arg = fmt.Sprintf(arg, getConfigPath(cadir))
		case updateDbPassphraseIndex:
			arg = fmt.Sprintf(arg, getPassphraseFilePath(cadir))
		}

		args = append(args, arg)
	}

	return args
}

func updatedb(c *Config, isRootCa bool) {
	log.Printf("Updating the certificate database.")
	exitCode, standardOutput, standardError := common.InvokeOpensslCommand(genUpdateDbArgs(c, isRootCa)...)

	if exitCode != 0 {
		panic(fmt.Sprintf(
			"openssl invocation returned non-zero exit code: %d\n\nStdOut:\n%s\nStdErr:\n%s\n",
			exitCode,
			standardOutput,
			standardError))
	}
}

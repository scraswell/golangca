package openssl

import (
	"fmt"
	"log"

	"github.com/scraswell/golangca/openssl/common"
)

const genCrlConfigIndex = 2
const genCrlOutputPathIndex = 5
const genCrlPassphraseIndex = 7

var crlArgs = [...]string{
	"ca",
	"-config",
	"%s",
	"-gencrl",
	"-out",
	"%s",
	"-passin",
	"file:%s",
}

func genCrlArgs(c *Config, isRoot bool) []string {
	var args []string
	var cadir string

	if isRoot {
		cadir = c.RootCaConfig.Directory
	} else {
		cadir = c.IntermediateCaConfig.Directory
	}

	for i, arg := range crlArgs {
		switch i {
		case genCrlConfigIndex:
			arg = fmt.Sprintf(arg, getConfigPath(cadir))
		case genCrlOutputPathIndex:
			arg = fmt.Sprintf(arg, getCrlPath(cadir))
		case genCrlPassphraseIndex:
			arg = fmt.Sprintf(arg, getPassphraseFilePath(cadir))
		}

		args = append(args, arg)
	}

	return args
}

func generateCrl(c *Config, isRoot bool) {
	log.Print("Generating CRL...")
	exitCode, standardOutput, standardError := common.InvokeOpensslCommand(genCrlArgs(c, isRoot)...)

	if exitCode != 0 {
		panic(fmt.Sprintf(
			"openssl invocation returned non-zero exit code: %d\n\nStdOut:\n%s\nStdErr:\n%s\n",
			exitCode,
			standardOutput,
			standardError))
	}
}

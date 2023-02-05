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

func genCrlArgs(isRoot bool) []string {
	var c = GetConfig()
	var args []string
	var caDir string

	if isRoot {
		caDir = c.RootCaConfig.Directory
	} else {
		caDir = c.IntermediateCaConfig.Directory
	}

	for i, arg := range crlArgs {
		switch i {
		case genCrlConfigIndex:
			arg = fmt.Sprintf(arg, getConfigPath(caDir))
		case genCrlOutputPathIndex:
			arg = fmt.Sprintf(arg, getCrlPath(caDir))
		case genCrlPassphraseIndex:
			arg = fmt.Sprintf(arg, getPassphraseFilePath(caDir))
		}

		args = append(args, arg)
	}

	return args
}

func GenerateCrl(isRoot bool) {
	log.Print("Generating CRL...")
	exitCode, standardOutput, standardError := common.InvokeOpensslCommand(genCrlArgs(isRoot)...)

	if exitCode != 0 {
		panic(fmt.Sprintf(
			"openssl invocation returned non-zero exit code: %d\n\nStdOut:\n%s\nStdErr:\n%s\n",
			exitCode,
			standardOutput,
			standardError))
	}
}

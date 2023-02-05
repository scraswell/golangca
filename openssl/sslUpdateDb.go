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

func genUpdateDbArgs(isRootCa bool) []string {
	var caDir string
	var c = GetConfig()

	if isRootCa {
		caDir = c.RootCaConfig.Directory
	} else {
		caDir = c.IntermediateCaConfig.Directory
	}

	var args []string

	for i, arg := range updateDbArgs {
		switch i {
		case updateDbConfigIndex:
			arg = fmt.Sprintf(arg, getConfigPath(caDir))
		case updateDbPassphraseIndex:
			arg = fmt.Sprintf(arg, getPassphraseFilePath(caDir))
		}

		args = append(args, arg)
	}

	return args
}

func Updatedb(isRootCa bool) {
	log.Printf("Updating the certificate database.")
	exitCode, standardOutput, standardError := common.InvokeOpensslCommand(genUpdateDbArgs(isRootCa)...)

	if exitCode != 0 {
		panic(fmt.Sprintf(
			"openssl invocation returned non-zero exit code: %d\n\nStdOut:\n%s\nStdErr:\n%s\n",
			exitCode,
			standardOutput,
			standardError))
	}
}

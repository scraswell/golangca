package openssl

import (
	"fmt"

	"github.com/scraswell/golangca/openssl/common"
)

const testPassphraseKeyFileIndex = 3
const testPassphraseFileIndex = 5

var testPassphraseArgs = [...]string{
	"rsa",
	"-noout",
	"-in",
	"%s",
	"-passin",
	"file:%s",
}

func genTestPassphraseArgs(isRoot bool) []string {
	var args []string
	caDir := getCaDir(isRoot)

	for i, arg := range testPassphraseArgs {
		switch i {
		case testPassphraseKeyFileIndex:
			arg = fmt.Sprintf(arg, getPrivateKeyPath(caDir))
		case testPassphraseFileIndex:
			arg = fmt.Sprintf(arg, getPassphraseFilePath(caDir))
		}

		args = append(args, arg)
	}

	return args
}

func TestKeyPassphrase(isRoot bool) {
	exitCode, standardOutput, standardError := common.InvokeOpensslCommand(genTestPassphraseArgs(isRoot)...)

	if exitCode != 0 {
		panic(fmt.Sprintf(
			"openssl invocation returned non-zero exit code: %d\n\nStdOut:\n%s\nStdErr:\n%s\n",
			exitCode,
			standardOutput,
			standardError))
	}
}

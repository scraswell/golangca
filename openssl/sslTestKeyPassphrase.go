package openssl

import (
	"fmt"
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

func genTestPassphraseArgs(c *Config, isRoot bool) []string {
	var args []string
	cadir := getCaDir(c, isRoot)

	for i, arg := range testPassphraseArgs {
		switch i {
		case testPassphraseKeyFileIndex:
			arg = fmt.Sprintf(arg, getPrivateKeyPath(cadir))
		case testPassphraseFileIndex:
			arg = fmt.Sprintf(arg, getPassphraseFilePath(cadir))
		}

		args = append(args, arg)
	}

	return args
}

func TestKeyPassphrase(c *Config, isRoot bool) {
	exitCode, standardOutput, standardError := InvokeOpensslCommand(genTestPassphraseArgs(c, isRoot)...)

	if exitCode != 0 {
		panic(fmt.Sprintf(
			"openssl invocation returned non-zero exit code: %d\n\nStdOut:\n%s\nStdErr:\n%s\n",
			exitCode,
			standardOutput,
			standardError))
	}
}

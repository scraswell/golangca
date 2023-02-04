package openssl

import (
	"fmt"

	"github.com/scraswell/golangca/openssl/common"
)

const genRsaKeyPassphraseIndex = 3
const genRsaKeyOutputFileIndex = 5
const genRsaKeyBitLengthIndex = 6

var encryptedRsaKeyArgs = [...]string{
	"genrsa",
	"-aes256",
	"-passout",
	"pass:%s",
	"-out",
	"%s",
	"%d",
}

func getGenEncryptedRsaKeyArgs(passphrase string, keyfilePath string, bitlength int) []string {
	var args []string

	for i, arg := range encryptedRsaKeyArgs {
		switch i {
		case genRsaKeyPassphraseIndex:
			arg = fmt.Sprintf(arg, passphrase)
		case genRsaKeyOutputFileIndex:
			arg = fmt.Sprintf(arg, keyfilePath)
		case genRsaKeyBitLengthIndex:
			arg = fmt.Sprintf(arg, bitlength)
		}

		args = append(args, arg)
	}

	return args
}

func GenerateEncryptedRsaKey(passphrase string, keyfilePath string, bitlength int) {
	exitCode, standardOutput, standardError := common.InvokeOpensslCommand(
		getGenEncryptedRsaKeyArgs(passphrase, keyfilePath, bitlength)...)

	protectFile(keyfilePath)

	if exitCode != 0 {
		panic(fmt.Sprintf(
			"openssl invocation returned non-zero exit code: %d\n\nStdOut:\n%s\nStdErr:\n%s\n",
			exitCode,
			standardOutput,
			standardError))
	}
}

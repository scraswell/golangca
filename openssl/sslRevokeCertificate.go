package openssl

import (
	"fmt"
	"log"

	"github.com/scraswell/golangca/openssl/common"
)

const revokeCertificateConfigIndex = 2
const revokeCertificateIndex = 4
const revokeCertificatePassphraseIndex = 6

var revokeCertificateArgs = [...]string{
	"ca",
	"-config",
	"%s",
	"-revoke",
	"%s",
	"-passin",
	"file:%s",
}

func genRevokeCertificateArgs(isRoot bool, certificateSerialNumber string) []string {
	var args []string
	var caDir string
	var c = GetConfig()

	if isRoot {
		caDir = c.RootCaConfig.Directory
	} else {
		caDir = c.IntermediateCaConfig.Directory
	}

	for i, arg := range revokeCertificateArgs {
		switch i {
		case revokeCertificateConfigIndex:
			arg = fmt.Sprintf(arg, getConfigPath(caDir))
		case revokeCertificateIndex:
			arg = fmt.Sprintf(arg, fmt.Sprintf("%s/%s.pem", getIssuedCertsDir(caDir), certificateSerialNumber))
		case revokeCertificatePassphraseIndex:
			arg = fmt.Sprintf(arg, getPassphraseFilePath(caDir))
		}

		args = append(args, arg)
	}

	return args
}

func RevokeCertificate(isRoot bool, certificateSerialNumber string) {
	log.Printf("Revoking certificate with serial number %s...", certificateSerialNumber)
	exitCode, standardOutput, standardError := common.InvokeOpensslCommand(genRevokeCertificateArgs(isRoot, certificateSerialNumber)...)

	if exitCode != 0 {
		panic(fmt.Sprintf(
			"openssl invocation returned non-zero exit code: %d\n\nStdOut:\n%s\nStdErr:\n%s\n",
			exitCode,
			standardOutput,
			standardError))
	}
}

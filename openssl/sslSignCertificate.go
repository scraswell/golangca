package openssl

import (
	"fmt"
	"log"

	common "github.com/scraswell/golangca/openssl/common"
)

const signingConfigIndex = 2
const signingExtensionsIndex = 4
const signingDaysValid = 6
const signingHashAlgorithmIndex = 9
const signingPassphraseIndex = 11
const signingRequestIndex = 14
const signingOutputIndex = 16

var certificateSigningArgs = [...]string{
	"ca",
	"-config",
	"%s",
	"-extensions",
	"%s",
	"-days",
	"%d",
	"-notext",
	"-md",
	"%s",
	"-passin",
	"file:%s",
	"-batch",
	"-in",
	"%s",
	"-out",
	"%s",
}

func genSigningCommandArgs(signingParams *SigningParams) []string {
	var args []string

	for i, arg := range certificateSigningArgs {
		switch i {
		case signingConfigIndex:
			arg = fmt.Sprintf(arg, signingParams.OpensslConfig)
		case signingExtensionsIndex:
			arg = fmt.Sprintf(arg, signingParams.Policy)
		case signingDaysValid:
			arg = fmt.Sprintf(arg, signingParams.DaysValid)
		case signingHashAlgorithmIndex:
			arg = fmt.Sprintf(arg, signingParams.HashAlgorithm)
		case signingPassphraseIndex:
			arg = fmt.Sprintf(arg, signingParams.Passphrase)
		case signingRequestIndex:
			arg = fmt.Sprintf(arg, signingParams.CsrInputPath)
		case signingOutputIndex:
			arg = fmt.Sprintf(arg, signingParams.CertificateOutputPath)
		}

		args = append(args, arg)
	}

	return args
}

func SignCertificate(signingParams *SigningParams) string {
	log.Printf("Signing certificate request in: %s", signingParams.CsrInputPath)
	exitCode, standardOutput, standardError := common.InvokeOpensslCommand(
		genSigningCommandArgs(signingParams)...)

	if exitCode != 0 {
		panic(fmt.Sprintf(
			"openssl invocation returned non-zero exit code: %d\n\nStdOut:\n%s\nStdErr:\n%s\n",
			exitCode,
			standardOutput,
			standardError))
	}

	return signingParams.CertificateOutputPath
}

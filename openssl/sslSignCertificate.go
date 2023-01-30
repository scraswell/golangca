package openssl

import "fmt"

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
	"pass:%s",
	"-batch",
	"-in",
	"%s",
	"-out",
	"%s",
}

func genSigningCommandArgs(signingParams *SigningParams) []string {
	var args []string

	for i, arg := range certificateSigningArgs {
		if i == signingConfigIndex {
			arg = fmt.Sprintf(arg, signingParams.OpensslConfig)
		} else if i == signingExtensionsIndex {
			arg = fmt.Sprintf(arg, signingParams.Policy)
		} else if i == signingDaysValid {
			arg = fmt.Sprintf(arg, signingParams.DaysValid)
		} else if i == signingHashAlgorithmIndex {
			arg = fmt.Sprintf(arg, signingParams.HashAlgorithm)
		} else if i == signingPassphraseIndex {
			arg = fmt.Sprintf(arg, signingParams.Passphrase)
		} else if i == signingRequestIndex {
			arg = fmt.Sprintf(arg, signingParams.CsrInputPath)
		} else if i == signingOutputIndex {
			arg = fmt.Sprintf(arg, signingParams.CertificateOutputPath)
		}

		args = append(args, arg)
	}

	return args
}

func SignCertificate(signingParams *SigningParams) string {
	exitCode, standardOutput, standardError := InvokeOpensslCommand(
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

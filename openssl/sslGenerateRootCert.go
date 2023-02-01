package openssl

import (
	"fmt"

	common "github.com/scraswell/golangca/openssl/common"
)

const genRootCaConfigIndex = 2
const genRootCaKeyIndex = 4
const genRootCaValidityDaysIndex = 8
const genRootCaValidityHashAlg = 9
const genRootCaDnIndex = 13
const genRootCaOutputFileIndex = 15
const genRootCaPassphraseIndex = 17

var rootCertArgs = [...]string{
	"req",
	"-config",
	"%s",
	"-key",
	"%s",
	"-new",
	"-x509",
	"-days",
	"%d",
	"-%s",
	"-extensions",
	"v3_ca",
	"-subj",
	"%s",
	"-out",
	"%s",
	"-passin",
	"file:%s",
}

func genRootCaCertificateArgs(c *Config) []string {
	var args []string

	for i, arg := range rootCertArgs {
		switch i {
		case genRootCaConfigIndex:
			arg = fmt.Sprintf(arg, getConfigPath(c.RootCaConfig.Directory))
		case genRootCaKeyIndex:
			arg = fmt.Sprintf(arg, getPrivateKeyPath(c.RootCaConfig.Directory))
		case genRootCaValidityDaysIndex:
			arg = fmt.Sprintf(arg, c.RootCaConfig.DaysValid)
		case genRootCaValidityHashAlg:
			arg = fmt.Sprintf(arg, c.HashAlgorithm)
		case genRootCaDnIndex:
			arg = BuildDistinguishedName(c, true)
		case genRootCaOutputFileIndex:
			arg = fmt.Sprintf(arg, getCaCertificatePath(c.RootCaConfig.Directory))
		case genRootCaPassphraseIndex:
			arg = fmt.Sprintf(arg, getPassphraseFilePath(c.RootCaConfig.Directory))
		}

		args = append(args, arg)
	}

	return args
}

func GenerateRootCACertificate(c *Config) {
	exitCode, standardOutput, standardError := common.InvokeOpensslCommand(genRootCaCertificateArgs(c)...)

	if exitCode != 0 {
		panic(fmt.Sprintf(
			"openssl invocation returned non-zero exit code: %d\n\nStdOut:\n%s\nStdErr:\n%s\n",
			exitCode,
			standardOutput,
			standardError))
	}
}

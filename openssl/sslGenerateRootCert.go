package openssl

import (
	"fmt"
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
	"pass:%s",
}

func genRootCaCertificateArgs(c *Config) []string {
	var args []string

	for i, arg := range rootCertArgs {
		if i == genRootCaConfigIndex {
			arg = fmt.Sprintf(arg, getConfigPath(c.RootCaConfig.Directory, c.OpenSslConfigFile))
		} else if i == genRootCaKeyIndex {
			arg = fmt.Sprintf(arg, getPrivateKeyPath(c.RootCaConfig.Directory))
		} else if i == genRootCaValidityDaysIndex {
			arg = fmt.Sprintf(arg, c.RootCaConfig.DaysValid)
		} else if i == genRootCaValidityHashAlg {
			arg = fmt.Sprintf(arg, c.HashAlgorithm)
		} else if i == genRootCaDnIndex {
			arg = BuildDistinguishedName(c, true)
		} else if i == genRootCaOutputFileIndex {
			arg = fmt.Sprintf(arg, getCaCertificatePath(c.RootCaConfig.Directory))
		} else if i == genRootCaPassphraseIndex {
			arg = fmt.Sprintf(arg, c.RootCaConfig.Passphrase)
		}

		args = append(args, arg)
	}

	return args
}

func GenerateRootCACertificate(c *Config) {
	exitCode, standardOutput, standardError := InvokeOpensslCommand(genRootCaCertificateArgs(c)...)

	if exitCode != 0 {
		panic(fmt.Sprintf(
			"openssl invocation returned non-zero exit code: %d\n\nStdOut:\n%s\nStdErr:\n%s\n",
			exitCode,
			standardOutput,
			standardError))
	}
}

package openssl

import (
	"fmt"
	"log"
)

const genCsrConfigIndex = 2
const genCsrPrivateKeyIndex = 4
const genCsrHashAlgorithmIndex = 6
const genCsrDnIndex = 8
const genCsrOutputIndex = 10
const genCsrPassphraseIndex = 12

var csrArgs = [...]string{
	"req",
	"-config",
	"%s",
	"-key",
	"%s",
	"-new",
	"-%s",
	"-subj",
	"%s",
	"-out",
	"%s",
	"-passin",
	"pass:%s",
}

func genCsrArgs(csr *Csr, openSslConfigFile string, csrOutputPath string, passphrase string) []string {
	var args []string

	for i, arg := range csrArgs {
		switch i {
		case genCsrConfigIndex:
			arg = fmt.Sprintf(arg, openSslConfigFile)
		case genCsrPrivateKeyIndex:
			arg = fmt.Sprintf(arg, csr.PrivateKeyPath)
		case genCsrHashAlgorithmIndex:
			arg = fmt.Sprintf(arg, csr.HashAlgorithm)
		case genCsrDnIndex:
			arg = BuildDistinguishedNameFromCsr(csr)
		case genCsrOutputIndex:
			arg = fmt.Sprintf(arg, csrOutputPath)
		case genCsrPassphraseIndex:
			arg = fmt.Sprintf(arg, passphrase)
		}

		args = append(args, arg)
	}

	return args
}

func GenerateCsr(
	country string,
	state string,
	city string,
	organization string,
	organizationalUnit string,
	commonName string,
	emailAddress string,
	hashAlgorithm string,
	privateKeyFilePath string,
	openSslConfigFile string,
	csrOutputPath string,
	passphrase string) {

	csr := Csr{
		Country:            country,
		State:              state,
		City:               city,
		Organization:       organization,
		OrganizationalUnit: organizationalUnit,
		CommonName:         commonName,
		EmailAddress:       emailAddress,
		HashAlgorithm:      hashAlgorithm,
		PrivateKeyPath:     privateKeyFilePath,
	}

	log.Printf("Generating certificate request for: (%s)", BuildDistinguishedNameFromCsr(&csr))
	exitCode, standardOutput, standardError := InvokeOpensslCommand(genCsrArgs(&csr, openSslConfigFile, csrOutputPath, passphrase)...)

	if exitCode != 0 {
		panic(fmt.Sprintf(
			"openssl invocation returned non-zero exit code: %d\n\nStdOut:\n%s\nStdErr:\n%s\n",
			exitCode,
			standardOutput,
			standardError))
	}
}

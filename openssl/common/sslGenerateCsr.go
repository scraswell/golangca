package common

import (
	"fmt"
	"log"
)

const genCsrPrivateKeyIndex = 2
const genCsrHashAlgorithmIndex = 4
const genCsrDnIndex = 6
const genCsrOutputIndex = 8
const genCsrPassphraseIndex = 10

var csrArgs = [...]string{
	"req",
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

func genCsrArgs(csr *Csr, csrOutputPath string, passphrase string) []string {
	var args []string

	for i, arg := range csrArgs {
		switch i {
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
	exitCode, standardOutput, standardError := InvokeOpensslCommand(genCsrArgs(&csr, csrOutputPath, passphrase)...)

	if exitCode != 0 {
		panic(fmt.Sprintf(
			"openssl invocation returned non-zero exit code: %d\n\nStdOut:\n%s\nStdErr:\n%s\n",
			exitCode,
			standardOutput,
			standardError))
	}
}

package openssl

import (
	"fmt"
	"log"
	"strings"

	"github.com/scraswell/golangca/openssl/common"
)

const getCertFilePathIndex = 2

var getCertArgs = [...]string{
	"x509",
	"-in",
	"%s",
	"-subject",
}

func genGetCertArgs(isRoot bool, getRootCaCertificate bool, serialNumber int) []string {
	var c = GetConfig()
	var args []string
	var caDir string
	var certPath string

	if isRoot {
		caDir = c.RootCaConfig.Directory
	} else {
		caDir = c.IntermediateCaConfig.Directory
	}

	if getRootCaCertificate {
		certPath = getCaCertificatePath(caDir)
	} else {
		certPath = fmt.Sprintf("%s/%d.pem", getIssuedCertsDir(caDir), serialNumber)
	}

	for i, arg := range getCertArgs {
		switch i {
		case getCertFilePathIndex:
			arg = fmt.Sprintf(arg, certPath)
		}

		args = append(args, arg)
	}

	return args
}

func GetCertificate(cert *common.GetCertificate) *common.EncodedCertificate {
	log.Print("Getting certificate...")

	exitCode, standardOutput, standardError := common.InvokeOpensslCommand(genGetCertArgs(cert.FromRootCa, cert.RootCert, cert.SerialNumber)...)

	if exitCode != 0 {
		panic(fmt.Sprintf(
			"openssl invocation returned non-zero exit code: %d\n\nStdOut:\n%s\nStdErr:\n%s\n",
			exitCode,
			standardOutput,
			standardError))
	}

	result := &common.EncodedCertificate{}
	outputLines := strings.Split(standardOutput, "\n")
	var pemEncodedCertLines []string

	for i, line := range outputLines {
		if i == 0 {
			result.Subject = strings.ReplaceAll(line, "subject= ", "")
		} else {
			pemEncodedCertLines = append(pemEncodedCertLines, line)
		}
	}

	result.EncodedCertificate = strings.Join(pemEncodedCertLines, "\n")

	return result
}

package openssl

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/scraswell/golangca/openssl/common"
)

const CertNotFoundError = "CertNotFoundError"
const getCertFilePathIndex = 2

var getCertArgs = [...]string{
	"x509",
	"-in",
	"%s",
	"-subject",
}

func genGetCertArgs(isRoot bool, getRootCaCertificate bool, serialNumber int) ([]string, bool) {
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

	return args, fileExists(certPath)
}

func GetCertificate(cert *common.GetCertificate) (*common.EncodedCertificate, error) {
	log.Print("Getting certificate...")

	args, exists := genGetCertArgs(cert.FromRootCa, cert.RootCert, cert.SerialNumber)
	if !exists {
		return nil, errors.New(CertNotFoundError)
	}

	exitCode, standardOutput, standardError := common.InvokeOpensslCommand(args...)

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

	return result, nil
}

func getCertificateFilePath(caDir string, serialNumber int) string {
	return fmt.Sprintf("%s/%d.pem", getIssuedCertsDir(caDir), serialNumber)
}

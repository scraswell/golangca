package openssl

import "fmt"

const CaCertFile string = "ca.cert.pem"
const CaKeyFile string = "ca.key.pem"
const CertsDir string = "certs"
const CrlDir string = "crl"
const CrlFile string = "int_ca.crl"
const CrlNumberFile string = "crlnumber"
const CrlUrl string = "https://authority.%s/%s"
const CsrDir string = "csr"
const DbFileName string = "index.txt"
const IntCaCert string = "int_ca.cert.pem"
const IntCaConfig string = "/int_ca-openssl.conf.j2"
const IntCaCsr string = "int_ca.csr"
const IntermediateCrlFile string = "int_ca.crl"
const IssuedDir string = "issued"
const PassphraseFile string = "passphrase"
const PassphraseLengthBytes = 128
const PfxDir string = "pfx"
const PrivateDir string = "private"
const RootCaConfig string = "/root_ca-openssl.conf.j2"
const RootCrlFile string = "ca.crl"
const SerialNumberFile string = "serial"
const StartingSerialNumber string = "1000"

var AuthorityDirs = [...]string{
	CertsDir,
	CrlDir,
	CsrDir,
	PrivateDir,
	PfxDir,
	IssuedDir,
}

func getConfigPath(caRoot string, configFileName string) string {
	return fmt.Sprintf("%s/%s", caRoot, configFileName)
}

func getPrivateKeyPath(caRoot string) string {
	return fmt.Sprintf("%s/%s/%s", caRoot, PrivateDir, CaKeyFile)
}

func getPassphraseFilePath(caRoot string) string {
	return fmt.Sprintf("%s/%s/%s", caRoot, PrivateDir, PassphraseFile)
}

func getCaCertificatePath(caRoot string) string {
	return fmt.Sprintf("%s/%s/%s", caRoot, CertsDir, CaCertFile)
}

func getCertOutputPath(caRoot string) string {
	return fmt.Sprintf("%s/%s", caRoot, CertsDir)
}

func getCsrPath(caRoot string) string {
	return fmt.Sprintf("%s/%s", caRoot, CsrDir)
}

func getCrlPath(caRoot string) string {
	return fmt.Sprintf("%s/%s/%s", caRoot, CrlDir, CrlFile)
}

func getCrlUrl(domain string, isRoot bool) string {
	var crlFile string

	if isRoot {
		crlFile = RootCrlFile
	} else {
		crlFile = IntermediateCrlFile
	}

	return fmt.Sprintf(CrlUrl, domain, crlFile)
}

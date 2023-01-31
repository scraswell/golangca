package openssl

import "fmt"

const CaCertFile string = "ca.cert.pem"
const CaKeyFile string = "ca.key.pem"
const CertsDir string = "certs"
const CrlDir string = "crl"
const CrlFile string = "ca.crl"
const CrlNumberFile string = "crlnumber"
const CrlUrl string = "https://authority.%s/%s"
const CsrDir string = "csr"
const DbFileName string = "index.txt"
const IntCaCert string = "int_ca.cert.pem"
const IntCaConfig string = "/int_ca-openssl.conf.j2"
const IntCaCsr string = "int_ca.csr"
const IssuedDir string = "issued"
const OpenSslConfigFileName string = "openssl.conf"
const PassphraseFile string = "passphrase"
const PassphraseLengthBytes = 128
const PfxDir string = "pfx"
const PrivateDir string = "private"
const PublishedIntermediateCrlFileName string = "int_ca.crl"
const PublishedRootCrlFileName string = "ca.crl"
const RootCaConfig string = "/root_ca-openssl.conf.j2"
const SerialNumberFile string = "serial"
const StartingCrlNumber string = "1000"
const StartingSerialNumber string = "1000"

var AuthorityDirs = [...]string{
	CertsDir,
	CrlDir,
	CsrDir,
	PrivateDir,
	PfxDir,
	IssuedDir,
}

func getCaDir(c *Config, isRoot bool) string {
	if isRoot {
		return c.RootCaConfig.Directory
	} else {
		return c.IntermediateCaConfig.Directory
	}
}

func getIssuedCertsDir(caRoot string) string {
	return fmt.Sprintf("%s/%s", caRoot, IssuedDir)
}

func getCrlNumberPath(caRoot string) string {
	return fmt.Sprintf("%s/%s", caRoot, CrlNumberFile)
}

func getConfigPath(caRoot string) string {
	return fmt.Sprintf("%s/%s", caRoot, OpenSslConfigFileName)
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
		crlFile = PublishedRootCrlFileName
	} else {
		crlFile = PublishedIntermediateCrlFileName
	}

	return fmt.Sprintf(CrlUrl, domain, crlFile)
}

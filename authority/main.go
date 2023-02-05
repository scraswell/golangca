package authority

import (
	"github.com/scraswell/golangca/openssl"
	"github.com/spf13/viper"
)

func init() {
	openssl.Initialize(false)
}

func GetRootCertificate() string {
	return openssl.GetRootCertificate()
}

func GetCrlForRootCa() string {
	return openssl.GetCrl(true)
}

func GetCrlForIntermediateCa() string {
	return openssl.GetCrl(false)
}

func RevokeRootCaCertificate(certificateSerialNumber string) {
	openssl.RevokeCertificate(true, certificateSerialNumber)
}

func RevokeIntermediateCaCertificate(certificateSerialNumber string) {
	openssl.RevokeCertificate(false, certificateSerialNumber)
}

func GenerateRootCaCrl() {
	openssl.GenerateCrl(true)
}

func GenerateIntermediateCaCrl() {
	openssl.GenerateCrl(false)
}

func UpdateRootCertificateDatabase() {
	openssl.Updatedb(true)
}

func UpdateIntermediateCertificateDatabase(v *viper.Viper) {
	openssl.Updatedb(false)
}

func ListRootCertificates() string {
	return openssl.ListCertificates(true)
}

func ListIntermediateCertificates() string {
	return openssl.ListCertificates(false)
}

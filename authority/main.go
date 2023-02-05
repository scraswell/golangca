package authority

import (
	"github.com/scraswell/golangca/openssl"
	"github.com/scraswell/golangca/openssl/common"
	"github.com/spf13/viper"
)

func init() {
	openssl.Initialize(false)
}

func GetCertificate(req *common.GetCertificate) (*common.EncodedCertificate, error) {
	return openssl.GetCertificate(req)
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
	openssl.UpdateDb(true)
}

func UpdateIntermediateCertificateDatabase(v *viper.Viper) {
	openssl.UpdateDb(false)
}

func ListRootCertificates() []*common.Certificate {
	return openssl.ListCertificates(true)
}

func ListIntermediateCertificates() []*common.Certificate {
	return openssl.ListCertificates(false)
}

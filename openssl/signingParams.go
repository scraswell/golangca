package openssl

const RootCAPolicy = "v3_ca"
const IntermediateCAPolicy = "v3_intermediate_ca"

type SigningParams struct {
	OpensslConfig         string
	Policy                string
	DaysValid             int
	HashAlgorithm         string
	Passphrase            string
	CsrInputPath          string
	CertificateOutputPath string
}

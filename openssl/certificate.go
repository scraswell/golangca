package openssl

// Tab delimited index database
// status
// date
// serial number
// file path; always unknown in db file
// distinguished name

const CertificateValid = "V"
const CertificateRevoked = "R"
const CertificateExpired = "E"

type Certificate struct {
	Status            string
	Date              string
	Serial            int
	FilePath          string
	DistinguishedName string
}

package common

// Tab delimited index database
// status
// date
// unknown (unused?)  double tab in the file...
// serial number
// file path; always unknown in db file
// distinguished name

const StatusField = 0
const DateField = 1
const SerialField = 3
const FilePathField = 4
const DistinguishedNameField = 5

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

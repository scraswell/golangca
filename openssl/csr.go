package openssl

type Csr struct {
	PrivateKeyPath     string
	HashAlgorithm      string
	Country            string
	State              string
	City               string
	Organization       string
	OrganizationalUnit string
	CommonName         string
	EmailAddress       string
}

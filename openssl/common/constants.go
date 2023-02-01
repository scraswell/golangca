package common

import "fmt"

const DistinguishedNameTemplate = "/C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s/emailAddress=%s"

func BuildDistinguishedNameFromCsr(csr *Csr) string {
	return fmt.Sprintf(
		DistinguishedNameTemplate,
		csr.Country,
		csr.State,
		csr.City,
		csr.Organization,
		csr.OrganizationalUnit,
		csr.CommonName,
		csr.EmailAddress)
}

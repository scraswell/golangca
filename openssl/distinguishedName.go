package openssl

import (
	"fmt"
)

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

func BuildDistinguishedName(c *Config, isRoot bool) string {
	var cn string
	var contact string

	if isRoot {
		cn = c.RootCaConfig.Name
		contact = c.RootCaConfig.Contact
	} else {
		cn = c.IntermediateCaConfig.Name
		contact = c.IntermediateCaConfig.Contact
	}

	return fmt.Sprintf(
		DistinguishedNameTemplate,
		c.Country,
		c.State,
		c.City,
		c.Org,
		c.OrgUnit,
		cn,
		contact)
}

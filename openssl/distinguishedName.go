package openssl

import (
	"fmt"

	"github.com/scraswell/golangca/openssl/common"
)

func BuildDistinguishedName(isRoot bool) string {
	var cn string
	var contact string
	var c = GetConfig()

	if isRoot {
		cn = c.RootCaConfig.Name
		contact = c.RootCaConfig.Contact
	} else {
		cn = c.IntermediateCaConfig.Name
		contact = c.IntermediateCaConfig.Contact
	}

	return fmt.Sprintf(
		common.DistinguishedNameTemplate,
		c.Country,
		c.State,
		c.City,
		c.Org,
		c.OrgUnit,
		cn,
		contact)
}

package openssl

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	openssl "github.com/scraswell/golangca/openssl/common"
)

func getDbFilePath(c *Config, fromRootCa bool) string {
	var dir string

	if fromRootCa {
		dir = c.RootCaConfig.Directory
	} else {
		dir = c.IntermediateCaConfig.Directory
	}

	return fmt.Sprintf("%s/%s", dir, DbFileName)
}

func listCertificates(c *Config, fromRootCa bool) string {
	dbFilePath := getDbFilePath(c, fromRootCa)

	db, err := os.Open(dbFilePath)

	if err != nil {
		panic(fmt.Errorf("unable to open certificate database: %w", err))
	}

	defer db.Close()

	reader := csv.NewReader(db)
	reader.Comma = '\t'
	reader.FieldsPerRecord = -1

	certificateData, err := reader.ReadAll()
	if err != nil {
		panic(fmt.Errorf("unable to read database: %w", err))
	}

	var certificate openssl.Certificate
	var certificates []openssl.Certificate

	for _, cert := range certificateData {
		certificate.Status = cert[openssl.StatusField]
		certificate.Date = cert[openssl.DateField]
		certificate.Serial, _ = strconv.Atoi(cert[openssl.SerialField])
		certificate.FilePath = fmt.Sprintf("./%s/%s.pem", IssuedDir, cert[openssl.SerialField])
		certificate.DistinguishedName = cert[openssl.DistinguishedNameField]

		certificates = append(certificates, certificate)
	}

	certsJson, err := json.Marshal(certificates)
	if err != nil {
		panic(fmt.Errorf("unable to marshall certificates: %w", err))
	}

	return string(certsJson)
}

package openssl

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
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
		panic(fmt.Errorf("Unable to open certificate database: %w", err))
	}

	defer db.Close()

	reader := csv.NewReader(db)
	reader.Comma = '\t'
	reader.FieldsPerRecord = -1

	certificateData, err := reader.ReadAll()
	if err != nil {
		panic(fmt.Errorf("Unable to read database: %w", err))
	}

	var certificate Certificate
	var certificates []Certificate

	for _, cert := range certificateData {
		certificate.Status = cert[StatusField]
		certificate.Date = cert[DateField]
		certificate.Serial, _ = strconv.Atoi(cert[SerialField])
		certificate.FilePath = fmt.Sprintf("./%s/%s.pem", IssuedDir, cert[SerialField])
		certificate.DistinguishedName = cert[DistinguishedNameField]

		certificates = append(certificates, certificate)
	}

	certsJson, err := json.Marshal(certificates)
	if err != nil {
		panic(fmt.Errorf("Unable to marshall certificates: %w", err))
	}

	return string(certsJson)
}

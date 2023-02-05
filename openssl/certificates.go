package openssl

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"

	"github.com/scraswell/golangca/openssl/common"
)

func GetRootCertificate() string {
	return readStringFromFile(getCaCertificatePath(GetConfig().RootCaConfig.Directory))
}

func ListCertificates(fromRootCa bool) []*common.Certificate {
	dbFilePath := getDbFilePath(fromRootCa)

	db, err := os.Open(dbFilePath)

	if err != nil {
		panic(fmt.Errorf("unable to open certificate database: %w", err))
	}

	reader := csv.NewReader(db)
	reader.Comma = '\t'
	reader.FieldsPerRecord = -1

	certificateData, err := reader.ReadAll()
	if err != nil {
		panic(fmt.Errorf("unable to read database: %w", err))
	}

	var certificate common.Certificate
	var certificates []*common.Certificate

	for _, cert := range certificateData {
		certificate.Status = cert[common.StatusField]
		certificate.Date = cert[common.DateField]
		certificate.Serial, _ = strconv.Atoi(cert[common.SerialField])
		certificate.FilePath = fmt.Sprintf("./%s/%s.pem", IssuedDir, cert[common.SerialField])
		certificate.DistinguishedName = cert[common.DistinguishedNameField]

		certificates = append(certificates, &certificate)
	}

	closeFile(db)

	return certificates
}

func getDbFilePath(fromRootCa bool) string {
	var dir string

	if fromRootCa {
		dir = GetConfig().RootCaConfig.Directory
	} else {
		dir = GetConfig().IntermediateCaConfig.Directory
	}

	return fmt.Sprintf("%s/%s", dir, DbFileName)
}

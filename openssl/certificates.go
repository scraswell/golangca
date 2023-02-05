package openssl

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/scraswell/golangca/openssl/common"
)

func GetRootCertificate() string {
	return readStringFromFile(getCaCertificatePath(GetConfig().RootCaConfig.Directory))
}

func ListCertificates(fromRootCa bool) string {
	dbFilePath := getDbFilePath(fromRootCa)

	db, err := os.Open(dbFilePath)

	if err != nil {
		panic(fmt.Errorf("unable to open certificate database: %w", err))
	}

	defer func(db *os.File) {
		err := db.Close()
		if err != nil {
			panic(fmt.Errorf("failed to close file %w", err))
		}
	}(db)

	reader := csv.NewReader(db)
	reader.Comma = '\t'
	reader.FieldsPerRecord = -1

	certificateData, err := reader.ReadAll()
	if err != nil {
		panic(fmt.Errorf("unable to read database: %w", err))
	}

	var certificate common.Certificate
	var certificates []common.Certificate

	for _, cert := range certificateData {
		certificate.Status = cert[common.StatusField]
		certificate.Date = cert[common.DateField]
		certificate.Serial, _ = strconv.Atoi(cert[common.SerialField])
		certificate.FilePath = fmt.Sprintf("./%s/%s.pem", IssuedDir, cert[common.SerialField])
		certificate.DistinguishedName = cert[common.DistinguishedNameField]

		certificates = append(certificates, certificate)
	}

	certsJson, err := json.Marshal(certificates)
	if err != nil {
		panic(fmt.Errorf("unable to marshall certificates: %w", err))
	}

	return string(certsJson)
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

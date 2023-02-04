package common

import (
	"fmt"
	"os"
)

func ProtectFile(filePath string) {
	err := os.Chmod(filePath, os.FileMode.Perm(0o600))
	if err != nil {
		panic(fmt.Errorf("error changing the file mode (%s): %w", filePath, err))
	}
}

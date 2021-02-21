package peinfo

import (
	"debug/pe"
	"os"
	"path/filepath"
)

// Initialize returns the config for execution
func Initialize(filePath string, verbose bool, rootCertDir string, extractCert bool) (ConfigT, error) {
	fh, err := os.Open(filePath)
	if nil != err {
		return ConfigT{}, err
	}

	tempPE, err := pe.NewFile(fh)
	if nil != err {
		return ConfigT{}, err
	}

	file := ConfigT{
		FileName:    filepath.Base(filePath),
		OSFile:      fh,
		PEFile:      tempPE,
		Verbose:     verbose,
		ExtractCert: extractCert,
		RootCertDir: rootCertDir,
	}

	return file, nil
}

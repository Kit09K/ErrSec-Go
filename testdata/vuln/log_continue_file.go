//go:build ignore

package vuln

import (
	"log"
	"os"
)

// ReadConfigInsecure - ErrSec MUST report: [MEDIUM] LOG_CONTINUE at os.ReadFile()
func ReadConfigInsecure(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("failed to read config: %v", err)
	}
	return data
}

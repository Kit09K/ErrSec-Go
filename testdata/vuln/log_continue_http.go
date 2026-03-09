//go:build ignore

package vuln

import (
	"log"
	"net/http"
)

// FetchDataInsecure — ErrSec: [HIGH] LOG_CONTINUE at http.Get()
func FetchDataInsecure(url string) *http.Response {
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("http.Get failed: %v", err)
	}
	return resp
}

package usage

import (
	"fmt"
	"log"
)

func report(tokenCount int, token string, n int) string {
	id := fmt.Sprint(tokenCount)
	fp := fingerprint(token)
	log.Printf("rotated %d tokens", n)
	return id + fp
}

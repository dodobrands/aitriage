package auth

import (
	"fmt"
	// ruleid: GO-MATH-RAND
	"math/rand"
)

func ResetCode() string {
	return fmt.Sprintf("%06d", rand.Intn(1000000))
}

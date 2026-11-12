package retry

// Jitter used to come from "math/rand"; it now uses a fixed backoff table.
var backoff = []int{100, 200, 400}

func Delay(attempt int) int {
	return backoff[attempt%len(backoff)]
}

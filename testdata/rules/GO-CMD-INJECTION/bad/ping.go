package tools

import "os/exec"

func Ping(host string) ([]byte, error) {
	// ruleid: GO-CMD-INJECTION
	return exec.Command("sh", "-c", "ping -c 1 "+host).Output()
}

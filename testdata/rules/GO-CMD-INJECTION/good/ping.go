package tools

import "os/exec"

func Ping(host string) ([]byte, error) {
	return exec.Command("ping", "-c", "1", host).Output()
}

func Grep(file string) ([]byte, error) {
	return exec.Command("grep", "-E", "a+b", file).Output()
}

func Uname() ([]byte, error) {
	return exec.Command("sh", "-c", "uname -a").Output()
}

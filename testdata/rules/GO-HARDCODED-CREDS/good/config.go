package config

import "os"

const envDBPassword = "DB_PASSWORD"

func Password() string {
	dbPassword := os.Getenv(envDBPassword)
	prompt := "Password: "
	_ = prompt
	return dbPassword
}

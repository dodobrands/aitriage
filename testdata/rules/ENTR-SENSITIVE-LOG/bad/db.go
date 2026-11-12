package db

import "log"

func connect(cfg Config) {
	// ruleid: ENTR-SENSITIVE-LOG
	log.Printf("connecting as %s with %s", cfg.User, cfg.Password)
}

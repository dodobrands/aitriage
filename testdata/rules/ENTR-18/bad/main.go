package main

import "github.com/gin-gonic/gin"

func main() {
	// ruleid: ENTR-18
	gin.SetMode(gin.DebugMode)
	r := gin.Default()
	_ = r.Run(":8080")
}

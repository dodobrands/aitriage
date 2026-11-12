package main

import "github.com/gin-gonic/gin"

func main() {
	// Never ship gin.SetMode(gin.DebugMode).
	gin.SetMode(gin.ReleaseMode)
	addr := "0.0.0.0:8080"
	_ = gin.Default().Run(addr)
}

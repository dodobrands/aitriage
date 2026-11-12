package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func Fetch(c *gin.Context) {
	// ruleid: GO-SSRF
	req, _ := http.NewRequestWithContext(c, http.MethodGet, c.Query("target"), nil)
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

package ws

import (
	"net/http"

	"nhooyr.io/websocket"
)

// In this library the option disables the Origin check, not TLS verification.
func Accept(w http.ResponseWriter, r *http.Request) (*websocket.Conn, error) {
	return websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
}

package api

func status(loc Location) statusResponse {
	resp := statusResponse{OK: true, Path: loc.WriteFile()}
	return resp
}

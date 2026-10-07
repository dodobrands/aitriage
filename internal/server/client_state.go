package server

import "github.com/dodobrands/aitriage/internal/agent/llm"

func (s *Server) getLLMClient() llm.Client {
	s.llmMu.RLock()
	defer s.llmMu.RUnlock()
	return s.llmClient
}

func (s *Server) initializeLLMClient(cfg llm.Config) {
	s.llmMu.Lock()
	defer s.llmMu.Unlock()
	if s.llmClient != nil {
		return
	}
	client, err := llm.NewClient(cfg)
	if err == nil {
		s.llmClient = client
	}
}

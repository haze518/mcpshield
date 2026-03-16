package transport

import (
	"fmt"
	"net/http"
	"time"
)

type HTTPServerConfig struct {
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

// NewHTTPServer expects normalized timeouts; invalid zero/negative values are
// rejected.
func NewHTTPServer(addr string, handler http.Handler, cfg HTTPServerConfig) (*http.Server, error) {
	if err := validateHTTPServerConfig(cfg); err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}, nil
}

func validateHTTPServerConfig(cfg HTTPServerConfig) error {
	if cfg.ReadTimeout <= 0 {
		return fmt.Errorf("transport HTTP server read timeout must be > 0")
	}
	if cfg.WriteTimeout <= 0 {
		return fmt.Errorf("transport HTTP server write timeout must be > 0")
	}
	if cfg.IdleTimeout <= 0 {
		return fmt.Errorf("transport HTTP server idle timeout must be > 0")
	}
	return nil
}

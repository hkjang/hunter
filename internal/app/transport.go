package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"time"
)

func (a *App) trustedRoots(ctx context.Context) (*x509.CertPool, error) {
	s, e := a.setting(ctx, "security")
	if e != nil {
		return nil, e
	}
	pem := asString(s["trusted_ca_pem"])
	if pem == "" {
		return nil, nil
	}
	roots, e := x509.SystemCertPool()
	if e != nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM([]byte(pem)) {
		return nil, errors.New("내부 CA 인증서가 올바르지 않습니다")
	}
	return roots, nil
}
func (a *App) outboundClient(ctx context.Context, timeout time.Duration) (*http.Client, error) {
	roots, e := a.trustedRoots(ctx)
	if e != nil {
		return nil, e
	}
	return &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, ResponseHeaderTimeout: 45 * time.Second, MaxIdleConns: 10}, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

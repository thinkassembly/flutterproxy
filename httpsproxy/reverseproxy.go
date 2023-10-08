package httpsproxy

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// Proxy is a HTTPS reverse proxy. It is a man-in-the-middle proxy that intercepts and redirects
// requests to a HTTP host. It can optional forward the requests that match a list of path
// prefixes to the real HTTPS server.
type Proxy struct {
	cfg *tls.Config

	target     http.Handler
	targetHost string

	next     http.Handler
	nextHost string

	prefixes []string
}

// New returns a new HTTPS reverse proxy to a HTTP host, with an list of path prefixes that
// should be forwarded to the nextHost.
func New(cert tls.Certificate, targetHost, nextHost string, prefixes []string) (*Proxy, error) {
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		Certificates: []tls.Certificate{cert},
	}
	return &Proxy{cfg: cfg, targetHost: targetHost, nextHost: nextHost, prefixes: prefixes}, nil
}

// StartServer starts a HTTPS server for the reverse proxy.
func (hp *Proxy) StartServer() (string, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return "", err
	}

	targetURL, err := url.Parse("http://" + hp.targetHost)
	if err != nil {
		return "", err
	}

	nextURL, err := url.Parse("https://" + hp.nextHost)
	if err != nil {
		return "", err
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Director = makeDirector(proxy.Director, nextURL.Host)
	hp.target = proxy

	nextProxy := httputil.NewSingleHostReverseProxy(nextURL)
	nextProxy.Director = makeDirector(nextProxy.Director, nextURL.Host)
	hp.next = nextProxy

	port := listener.Addr().(*net.TCPAddr).Port
	addr := fmt.Sprintf("localhost:%d", port)

	srv := &http.Server{
		Addr:         addr,
		Handler:      hp,
		TLSConfig:    hp.cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	go srv.ServeTLS(listener, "", "")

	return addr, nil
}

// makeDirector a modified version of httputil.Director that sets http.Request.Host.
// The default httputil.NewSingleHostReverseProxy director ends in a loop.
func makeDirector(director func(*http.Request), host string) func(*http.Request) {
	return func(r *http.Request) {
		director(r)
		r.Host = host
	}
}

// ServeHTTP forwards requests to the next host if its path matches the given list of prefixes,
// otherwise it forwards the request to the masquerading HTTP host.
func (hp *Proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	for _, prefix := range hp.prefixes {
		if strings.HasPrefix(req.URL.Path, prefix) {
			log.Printf("%-8s NEXT     %v PATH %v", req.Method, req.Host, req.URL.Path)
			hp.next.ServeHTTP(w, req)
			return
		}
	}

	hp.target.ServeHTTP(w, req)
}

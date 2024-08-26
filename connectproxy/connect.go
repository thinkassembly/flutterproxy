// Package connectproxy implements a HTTP CONNECT proxy that supports man-in-the-middle
// interception of connections to a HTTPS server.
package connectproxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/thinkassembly/flutterproxy/fakeca"
	"github.com/thinkassembly/flutterproxy/httpsproxy"
)

// New returns a HTTP CONNECT proxy server.
func New(fakeCA *fakeca.FakeCA, hostPairs []string, prefixPairs []string, done chan<- bool) *Proxy {
	p := &Proxy{
		// redirectAddr: redirectAddr,
		FakeCA:    fakeCA,
		LocalMap:  make(map[string]string),
		RemoteMap: make(map[string]string),
		ProxyMap:  make(map[string]*domainInfo),
		PrefixMap: make(map[string][]string),
		done:      done,
	}

	for _, v := range hostPairs {
		parts := strings.Split(v, ",")
		if len(parts) == 2 {
			localHost := hostKey(parts[1])
			p.LocalMap[localHost] = parts[0]
			p.RemoteMap[parts[0]] = localHost
		}
	}

	for _, v := range prefixPairs {
		parts := strings.Split(v, ",")
		if len(parts) == 2 {
			p.PrefixMap[parts[0]] = append(p.PrefixMap[parts[0]], parts[1])
		}
	}

	return p
}

type domainInfo struct {
	proxyHost  string
	certPEM    []byte
	privKeyPEM []byte
	httpsProxy *httpsproxy.Proxy
}

// Proxy is a HTTP CONNECT proxy server.
type Proxy struct {
	FakeCA *fakeca.FakeCA

	redirectAddr string

	LocalMap  map[string]string
	RemoteMap map[string]string
	PrefixMap map[string][]string

	ProxyMap   map[string]*domainInfo
	proxyMutex sync.RWMutex

	done chan<- bool
}

func hostKey(host string) string {
	return strings.ReplaceAll(strings.TrimPrefix(host, "http://"), "127.0.0.1", "localhost")
}

// ServeHTTP handles HTTP CONNECT requests. It can also redirect a localhost URL to a HTTPS URL.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/quitquitquit" {
		p.done <- true
		return
	}
	if req.Method != http.MethodConnect {
		p.redirectToHTTPS(w, req)
		return
	}

	p.handleConnect(w, req)
}

func (p *Proxy) redirectToHTTPS(w http.ResponseWriter, req *http.Request) {
	if remoteHost, ok := p.LocalMap[hostKey(req.Host)]; ok {
		u := *req.URL
		u.Host = remoteHost
		if u.Scheme == "http" {
			u.Scheme = "https"
		}
		log.Printf("%-8s REDIRECT %s %s => %s", req.Method, req.Host, req.URL.String(), u.String())
		http.Redirect(w, req, u.String(), 307)
		return
	}

	http.Error(w, fmt.Sprintf("%-8s ERROR    %s %s", req.Method, req.Host, req.URL.String()), http.StatusMethodNotAllowed)
	return
}

func (p *Proxy) maybeStartHTTPSProxy(w http.ResponseWriter, req *http.Request) (string, error) {
	localHost, ok := p.RemoteMap[req.Host]
	if !ok {
		return "", nil
	}

	p.proxyMutex.RLock()
	proxyInfo, ok := p.ProxyMap[localHost]
	p.proxyMutex.RUnlock()
	if ok {
		return proxyInfo.proxyHost, nil
	}

	p.proxyMutex.Lock()
	defer p.proxyMutex.Unlock()

	proxyInfo, ok = p.ProxyMap[localHost]
	if ok {
		return proxyInfo.proxyHost, nil
	}

	host := req.URL.Hostname()
	certPEM, privKeyPEM, err := p.FakeCA.NewCert([]string{host})
	if err != nil {
		return "", err
	}

	// Create new HTTPS proxy.
	serverCert, err := tls.X509KeyPair(certPEM, privKeyPEM)
	if err != nil {
		return "", err
	}

	httpsProxy, err := httpsproxy.New(serverCert, localHost, req.Host, p.PrefixMap[req.Host])
	if err != nil {
		return "", err
	}

	addr, err := httpsProxy.StartServer()
	if err != nil {
		return "", err
	}

	p.ProxyMap[localHost] = &domainInfo{
		proxyHost:  addr,
		certPEM:    certPEM,
		privKeyPEM: privKeyPEM,
		httpsProxy: httpsProxy,
	}

	return addr, nil
}

func (p *Proxy) handleConnect(w http.ResponseWriter, req *http.Request) {
	log.Printf("%-8s PROXY    %s : %s", req.Method, req.Host, req.URL.String())

	remoteHost := req.Host

	proxyHost, err := p.maybeStartHTTPSProxy(w, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if proxyHost != "" {
		log.Printf("%-8s FORWARD  %v => %v : %v", req.Method, req.Host, proxyHost, p.RemoteMap[req.Host])
		remoteHost = proxyHost
	}

	log.Printf("%-8s DIAL     %s => %s", req.Method, req.Host, remoteHost)
	targetConn, err := net.Dial("tcp", remoteHost)
	if err != nil {
		log.Println("failed to dial to target", remoteHost)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
	hj, ok := w.(http.Hijacker)
	if !ok {
		log.Fatal("HTTP server doesn't support hijacking connection")
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		log.Fatal("HTTP hijacking failed")
	}

	if proxyHost != "" {
		log.Printf("%-8s TUNNEL   %s => %s", req.Method, req.Host, remoteHost)
	}
	go tunnelConn(targetConn, clientConn)
	go tunnelConn(clientConn, targetConn)
}

func tunnelConn(dst io.WriteCloser, src io.ReadCloser) {
	io.Copy(dst, src)
	dst.Close()
	src.Close()
}

// Binary flutterproxy is a man-in-the-middle reverse proxy for Flutter web app development.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/thinkassembly/flutterproxy/connectproxy"
	"github.com/thinkassembly/flutterproxy/fakeca"
)

type strList []string

func (sl *strList) String() string {
	return strings.Join(*sl, ";")
}

func (sl *strList) Set(value string) error {
	*sl = append(*sl, value)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		help()
	}

	switch os.Args[1] {
	case "genca":
		genca()
	case "run":
		run()
	case "usage":
		usage()
	default:
		help()
	}
}

func help() {
	fmt.Fprintf(flag.CommandLine.Output(), `Usage of %s:
  Supported commands [genca, run, usage]:
    genca - Generate fake CA certificate and private key files
    run   - Run the proxy
    usage - Show sample usage
`, os.Args[0])
	os.Exit(0)
}

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), `Sample usage of %s:

# Generate a fake CA.
%s genca --cert=secret/cert.pem --key=secret/key.pem

# OS specific: Add the fake CA's certificate to Chrome's CA certificate store.

# Start the proxy.
%s run --cert=secret/cert.pem --key=secret/key.pem --host_pair=yoursite.com:443,127.0.0.1:7777 --prefix_pair=yoursite.com:443,/api

# Run the Flutter app.
flutter run -d chrome --web-port=7777 --web-browser-flag=--proxy-server=http://127.0.0.1:9999 --web-browser-flag=--proxy-bypass-list="<-loopback>" --web-browser-flag=--disable-web-security --web-browser-flag=--allow-running-insecure-content

`, os.Args[0], os.Args[0], os.Args[0])
	os.Exit(0)
}

func genca() {
	fs := flag.NewFlagSet("genca", flag.ExitOnError)

	cert := fs.String("cert", "", "Fake CA certificate output file")
	key := fs.String("key", "", "Fake CA private key output file")

	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatalf("Parse flags error: %v", err)
	}

	for _, v := range []string{*cert, *key} {
		if err := os.MkdirAll(filepath.Dir(v), 0700); err != nil {
			log.Fatalf("Make output directory: %v", err)
		}
	}

	ca, err := fakeca.NewCA()
	if err != nil {
		log.Fatalf("Create CA error: %v", err)
	}

	if err := os.WriteFile(*key, ca.PrivKeyPEM, 0600); err != nil {
		log.Fatalf("Write CA private key error: %v", err)
	}

	if err := os.WriteFile(*cert, ca.CertPEM, 0600); err != nil {
		log.Fatalf("Write CA certificate error: %v", err)
	}
}

func run() {
	runCmd := flag.NewFlagSet("run", flag.ExitOnError)

	var addr = runCmd.String("addr", "127.0.0.1:9999", "HTTP CONNECT proxy address")
	var cert = runCmd.String("cert", "", "Fake CA certificate file")
	var key = runCmd.String("key", "", "Fake CA private key file")

	var hostPairs strList
	runCmd.Var(&hostPairs, "host_pair", "List of redirect host pairs: '<to>,<from>'")

	var prefixPairs strList
	runCmd.Var(&prefixPairs, "prefix_pair", "List of path prefixes to forward: '<host>,<path>'")

	if err := runCmd.Parse(os.Args[2:]); err != nil {
		log.Fatalf("Parse flags error: %v", err)
	}

	keyPEM, err := os.ReadFile(*key)
	if err != nil {
		log.Fatalf("Read CA private key error: %v", err)
	}

	certPEM, err := os.ReadFile(*cert)
	if err != nil {
		log.Fatalf("Read CA certificate error: %v", err)
	}

	fakeCA, err := fakeca.FromKeyPair(keyPEM, certPEM)
	if err != nil {
		log.Fatalf("Load CA error: %v", err)
	}

	ctx := context.Background()
	done := make(chan bool)

	proxy := connectproxy.New(fakeCA, hostPairs, prefixPairs, done)

	log.Println("Starting proxy server at", *addr)

	server := &http.Server{Addr: *addr, Handler: proxy}
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Print("ListenAndServe:", err)
		}
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}

	if err := server.Shutdown(ctx); err != nil {
		log.Fatal("Shutdown:", err)
	}
}

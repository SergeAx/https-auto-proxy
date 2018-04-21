package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"encoding/base64"
	"golang.org/x/crypto/acme/autocert"
	"os"
	"strings"
)

func authCheck(r *http.Request) string {
	authVar := os.Getenv("PROXY_AUTH")
	if len(authVar) == 0 {
		return ""
	}

	authHeader := strings.SplitN(r.Header.Get("Proxy-Authorization"), " ", 2)
	if len(authHeader) != 2 || strings.ToLower(authHeader[0]) != "basic" {
		return "Basic authorization required"
	}

	payload, err := base64.StdEncoding.DecodeString(authHeader[1])
	if err != nil {
		return "Invalid Proxy-Authorization header"
	}
	loginPair := strings.SplitN(string(payload), ":", 2)

	for _, userPass := range strings.Split(authVar, ";") {
		pair := strings.Split(userPass, ":")
		if len(pair) == 1 {
			if len(loginPair) == 1 && loginPair[0] == pair[0] {
				return ""
			}
		} else {
			if len(loginPair) == 2 && loginPair[0] == pair[0] && loginPair[1] == pair[1] {
				return ""
			}
		}
	}

	return "Login and/or password doesn't match"
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	if err := authCheck(r); err != "" {
		w.Header().Set("Proxy-Authenticate", "basic realm=proxy")
		http.Error(w, err, http.StatusProxyAuthRequired)
		return
	}

	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	if err := authCheck(r); err != "" {
		w.Header().Set("Proxy-Authenticate", "basic realm=proxy")
		http.Error(w, err, http.StatusProxyAuthRequired)
		return
	}

	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func getEnvOrFail(env string) (val string) {
	val = os.Getenv(env)
	if len(val) == 0 {
		log.Fatalf("%s env variable should be set", env)
	}
	return
}

// Todo: handling proxy headers like X-Forwarded-For, X-Real-IP, chain headers
// Todo: timeouts while copying data between two connections or the ones exposed by net/http

func main() {
	allowedHost := getEnvOrFail("HOST")
	adminEmail := getEnvOrFail("ADMIN_EMAIL")

	dataDir := "."
	hostPolicy := func(ctx context.Context, host string) error {
		if host == allowedHost {
			return nil
		}
		return fmt.Errorf("acme/autocert: only %s host is allowed", allowedHost)
	}

	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: hostPolicy,
		Cache:      autocert.DirCache(dataDir),
		Email:      adminEmail,
	}

	httpsSrv := &http.Server{
		Addr: ":443",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
		TLSConfig: &tls.Config{GetCertificate: manager.GetCertificate},
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	go func() {
		err := httpsSrv.ListenAndServeTLS("", "")
		if err != nil {
			log.Fatalf("httpsSrv.ListendAndServeTLS() failed with %s", err)
		}
	}()

	httpSrv := &http.Server{
		Addr:    ":80",
		Handler: manager.HTTPHandler(httpsSrv.Handler),
	}

	log.Fatal(httpSrv.ListenAndServe())
}

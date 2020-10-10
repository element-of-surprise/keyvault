package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/element-of-surprise/keyvault"
	"log"
)

const (
	clientID = "6d32e8c3-fec6-4f00-88eb-fe8d9427cbce"
	vault    = "keyvault-sdk-etoe"

	textSecret = "hello world"

	pkcs12SelfSigned = "test-pkcs12-selfsigned"
)

var client *keyvault.Client

func init() {
	msi, err := keyvault.MSIAuth(clientID, keyvault.PublicCloud)
	if err != nil {
		panic(err)
	}
	client, err = keyvault.New(vault, keyvault.PublicCloud, msi)
	if err != nil {
		panic(err)
	}
}

func TestSecretGet(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	secret, err := client.Secrets().Get(ctx, "text-secret", "")
	if err != nil {
		t.Fatalf("TestSecretGet: got err == %s", err)
	}
	if secret != textSecret {
		t.Fatalf("TestSecretGet: got %q, want %q", secret, textSecret)
	}

	bundle, err := client.Secrets().Bundle(ctx, "text-secret", "")
	if err != nil {
		panic(err)
	}
}

func TestList(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	secrets, err := client.Secrets().List(ctx, 100)
	if err != nil {
		t.Fatalf("TestList: got err == %s", err)
	}

	if len(secrets) < 1 {
		t.Fatalf("TestList: got %d secrets, wanted >= 1", len(secrets))
	}
}

func TestSecretVersions(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	versions, err := client.Secrets().Versions(ctx, "text-secret", 100)
	if err != nil {
		t.Fatalf("TestSecretVersions: got err == %s", err)
	}

	if len(versions) != 1 {
		t.Fatalf("TestSecretVersions: got %d secrets, wanted 1", len(versions))
	}
}

// TestServiceCert tests that we can grab a self-signed cert and then
// use it to start a https server. We skip verification of the cert because
// it is self-signed.
func TestServiceCertSelfSigned(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cert, err := client.TLS().ServiceCert(ctx, pkcs12SelfSigned, "", true)
	if err != nil {
		t.Fatalf("TestServiceCert: got err == %s, want err == nil", err)
	}

	addr := "127.0.0.1:42523"
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	srv := &http.Server{
		Addr:         addr,
		TLSConfig:    cfg,
		ReadTimeout:  time.Minute,
		WriteTimeout: time.Minute,
		Handler:      http.HandlerFunc(okHandler),
	}
	go func() {
		srv.ListenAndServeTLS("", "")
	}()

	start := time.Now()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	for {
		if time.Now().Sub(start) > 5*time.Second {
			break
		}
		var resp *http.Response
		resp, err = client.Get(fmt.Sprintf("https://%s", addr))
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		resp.Body.Close()
		break
	}
	if err != nil {
		t.Fatalf("TestServiceCert(ListenAndServeTLS): got err == %s, want err == nil", err)
	}

	if err := srv.Close(); err != nil {
		t.Fatalf("TestServiceCert(ListenAndServeTLS): got err == %s, want err == nil", err)
	}
}

func okHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ok"))
}

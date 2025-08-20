package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

type SecureWebApp struct {
 Appalachian  string `json:"app_name"`
	Domain      string `json:"domain"`
	Certificate []byte `json:"-"`
	PrivateKey  []byte `json:"-"`
}

type GenerateRequest struct {
	AppName string `json:"app_name"`
	Domain  string `json:"domain"`
}

type GenerateResponse struct {
	AppConfig string `json:"app_config"`
	Cert      string `json:"cert"`
	Key       string `json:"key"`
}

func generateCertificatePair() ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	pub := &priv.PublicKey
	cert := &x509.Certificate{
		SerialNumber: rand.Int63(),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:  []string{"localhost"},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, priv)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	return certPEM, privPEM, nil
}

func generateAppConfig(certPEM, privPEM []byte) string {
	return fmt.Sprintf(`
[app]
name = "%s"
domain = "%s"

[server]
cert = %x
key = %x
`, "My Secure Web App", "localhost", certPEM, privPEM)
}

func handleGenerate(w http.ResponseWriter, r *http.Request) {
	var req GenerateRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	certPEM, privPEM, err := generateCertificatePair()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	appConfig := generateAppConfig(certPEM, privPEM)
	resp := GenerateResponse{
		AppConfig: appConfig,
		Cert:      string(certPEM),
		Key:       string(privPEM),
	}
	json.NewEncoder(w).Encode(resp)
}

func main() {
	http.HandleFunc("/generate", handleGenerate)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
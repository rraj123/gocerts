package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
	"net/url"


)

func main() {
	createCerts()
	parseCerts()
}
func parseCerts() {
	// Read the certificate file
	certPEM, err := os.ReadFile("certificate.pem")
	if err != nil {
		fmt.Println("Error reading certificate file:", err)
		return
	}

	// Decode the PEM file
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		fmt.Println("Failed to decode PEM block containing certificate")
		return
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println("Error parsing certificate:", err)
		return
	}
	
	// Print the Subject of the certificate
	fmt.Println("Subject:", cert.Subject)

	// Extract and print the SPIFFE ID from the SANs
	for _, uri := range cert.URIs {
		if uri.Scheme == "spiffe" {
			fmt.Println("SPIFFE ID:", uri.String())
		}
	}

}

func createCerts() {
		// Generate a private key
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Println("Error generating private key:", err)
			return
		}
	
		// Create a certificate template
		spiffeID := "spiffe://example.org/service"
	
		uri, err := url.Parse(spiffeID)
		if err != nil {
			fmt.Println("Error parsing SPIFFE ID:", err)
			return
		}
	
		// Create a certificate template
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				Organization:  []string{"ACME Corp"},
				Country:       []string{"US"},
				Province:      []string{"California"},
				Locality:      []string{"San Francisco"},
				StreetAddress: []string{"1 Market St"},
				PostalCode:    []string{"94105"},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(1, 0, 0), // Valid for 1 year
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			URIs:                  []*url.URL{uri},
		}
	
		// Self-sign the certificate
		certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
		if err != nil {
			fmt.Println("Error creating certificate:", err)
			return
		}
	
		// Write the private key to a file
		privateKeyFile, err := os.Create("private_key.pem")
		if err != nil {
			fmt.Println("Error creating private key file:", err)
			return
		}
		defer privateKeyFile.Close()
	
		err = pem.Encode(privateKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
		if err != nil {
			fmt.Println("Error encoding private key:", err)
			return
		}
	
		// Write the certificate to a file
		certFile, err := os.Create("certificate.pem")
		if err != nil {
			fmt.Println("Error creating certificate file:", err)
			return
		}
		defer certFile.Close()
	
		err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
		if err != nil {
			fmt.Println("Error encoding certificate:", err)
			return
		}
	
		fmt.Println("Certificate and private key generated successfully.")
}
package main

import (
	"testing"
	"github.com/stretchr/testify/suite"
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
	"io/ioutil"


)
type ExampleSuite struct {
	suite.Suite
	tempDir string

}

func TestExampleSuite(t *testing.T) {
	// Create a temporary directory for the test
	suite.Run(t, &ExampleSuite{})
}

func (es *ExampleSuite) TestTrue() {
	es.T().Log("Running TestTrue")
	es.True(true)
}

func (es *ExampleSuite) TestFalse() {
	es.T().Log("Running TestFalse")
	es.False(false)
}


func (es *ExampleSuite) SetupSuite() {
	es.T().Log("SetupSuite")
	// createTempCerts()
	var err error
	es.tempDir, err = ioutil.TempDir("", "SetupSuite ")
	if err != nil {
		es.T().Fatal("Failed to create temp dir:", err)
	}
}


func (es *ExampleSuite) TearDownSuite() {
	es.T().Log("TearDownSuite")
	err := os.RemoveAll(es.tempDir)
	if err != nil {
		es.T().Log("Failed to remove temp dir:", err)
	}
}


func (es *ExampleSuite) SetupTest() {
	createSetupCerts(es.tempDir)
	es.T().Log("SetupTest")
}


func (es *ExampleSuite) BeforeTest(suiteName, testName string) {
	es.T().Log("BeforeTest")
}


func (es *ExampleSuite) AfterTest(suiteName, testName string) {
	es.T().Log("AfterTest")
}

func createSetupCerts(tmpDir string) {
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
	privateKeyPath := fmt.Sprintf("%s/private_key.pem", tmpDir)
	privateKeyFile, err := os.Create(privateKeyPath)

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
	certFilePath := fmt.Sprintf("%s/private_key.pem", tmpDir)
	certFile, err := os.Create(certFilePath)
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
package utils

import (
	"crypto/x509"
	"io/ioutil"
	"os"

	"k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/klog"
)

type CertContext struct {
	Cert        []byte
	Key         []byte
	SigningCert []byte
}

// Setup the server cert. For example, user apiservers and admission webhooks
// can use the cert to prove their identify to the kube-apiserver
func SetupServerCert(namespaceName, serviceName string) *CertContext {
	certDir, err := ioutil.TempDir("", "webhook-cert")
	if err != nil {
		klog.Fatalf("Failed to create a temp dir for cert generation: %v", err)
	}
	defer os.RemoveAll(certDir)
	signingKey, err := NewPrivateKey()
	if err != nil {
		klog.Fatalf("Failed to create CA private key: %v", err)
	}
	signingCert, err := cert.NewSelfSignedCACert(cert.Config{CommonName: "webhook-ca"}, signingKey)
	if err != nil {
		klog.Fatalf("Failed to create CA cert for apiserver: %v", err)
	}
	key, err := NewPrivateKey()
	if err != nil {
		klog.Fatalf("Failed to create private key for : %v", err)
	}
	signedCert, err := NewSignedCert(
		&cert.Config{
			CommonName: serviceName + "." + namespaceName + ".svc",
			Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
		key, signingCert, signingKey,
	)
	if err != nil {
		klog.Fatalf("Failed to create cert : %v", err)
	}
	privateKeyPEM, err := keyutil.MarshalPrivateKeyToPEM(key)
	if err != nil {
		klog.Fatalf("Failed to marshal key %v", err)
	}
	return &CertContext{
		Cert:        EncodeCertPEM(signedCert),
		Key:         privateKeyPEM,
		SigningCert: EncodeCertPEM(signingCert),
	}
}
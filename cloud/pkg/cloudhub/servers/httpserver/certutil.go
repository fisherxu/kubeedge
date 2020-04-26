package httpserver

import (
	"crypto"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math"
	"math/big"
	"time"

	certutil "k8s.io/client-go/util/cert"

)
//NewCertificateAuthorityDer return certDer and key
func NewCertificateAuthorityDer() ([]byte, crypto.Signer, error) {
	cakey, err := NewPrivateKey()
	if err != nil {
		return nil, nil, nil
	}

	certDER, err := NewSelfSignedCACertDERBytes(cakey)
	if err != nil {
		return nil, nil, nil
	}

	cert, err :=x509.ParseCertificate(certDER)
	if err!=nil{
		fmt.Printf("%v",err)
	}
	WriteCertAndKey("/etc/kubeedge/ca/" , "rootCA" , cert, cakey)

	return certDER, cakey, nil
}

// NewPrivateKey creates an RSA private key
func NewPrivateKey() (crypto.Signer, error) {
	return rsa.GenerateKey(cryptorand.Reader, 2048)
}

// NewSelfSignedCACert creates a CA certificate
func NewSelfSignedCACertDERBytes(key crypto.Signer) ([]byte, error) {
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1024),
		Subject: pkix.Name{
			CommonName: "Kubeedge",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365 * 100),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDERBytes, err := x509.CreateCertificate(cryptorand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	return certDERBytes, err
}


func NewCloudCoreCertDERandKey(cfgs *certutil.Config) ([]byte,[]byte,error) {
	serverKey, _ := NewPrivateKey()
	keyDER := x509.MarshalPKCS1PrivateKey(serverKey.(*rsa.PrivateKey))
	//new CA
	_,caCert,caKey:= generateCaIfnotExist()

	//creates a signed certificate using the given CA certificate and key
	certDER, err :=NewCertFromCA(cfgs,caCert,serverKey,caKey)
	//serverCert, err :=x509.ParseCertificate(certDER)
	if err!=nil{
		fmt.Printf("%v",err)
	}
	return certDER,keyDER,err
}

//func NewCertFromCA(cfg *certutil.Config, caCert *x509.Certificate, clientkey crypto.Signer, caKey crypto.Signer) (*x509.Certificate,error) {
//NewCertFromCA create a certificate using giving CA
//func NewCertFromCA(cfg *certutil.Config, caCert *x509.Certificate, clientkey crypto.Signer, caKey crypto.Signer) ([]byte,error) {
//func NewCertFromCA(cfg *certutil.Config, caCert *x509.Certificate, clientkey crypto.PublicKey, caKey crypto.Signer) ([]byte,error) {
//	//key, _ := NewPrivateKey()
//	cert, err := NewSignedCert(cfg, caCert,clientkey,  caKey)
//	return cert, err
//}

// NewSignedCert creates a signed certificate using the given CA certificate and key
//func NewSignedCert(cfg *certutil.Config, clientpubkey crypto.Signer, caCert *x509.Certificate, caKey crypto.Signer) (*x509.Certificate, error) {
//func NewSignedCert(cfg *certutil.Config, clientKey crypto.Signer, caCert *x509.Certificate, caKey crypto.Signer) ([]byte, error) {
func NewCertFromCA(cfg *certutil.Config,  caCert *x509.Certificate,clientKey crypto.PublicKey, caKey crypto.Signer) ([]byte, error) {
	serial, err := cryptorand.Int(cryptorand.Reader, new(big.Int).SetInt64(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	if len(cfg.CommonName) == 0 {
		fmt.Println("must specify a CommonName")
		return nil, err
	}
	if len(cfg.Usages) == 0 {
		fmt.Println("must specify at least one ExtKeyUsage")
		return nil, err
	}

	certTmpl := x509.Certificate{
		Subject: pkix.Name{
			CommonName:   cfg.CommonName,
			Organization: cfg.Organization,
		},
		DNSNames:     cfg.AltNames.DNSNames,
		IPAddresses:  cfg.AltNames.IPs,
		SerialNumber: serial,
		NotBefore:    caCert.NotBefore,
		NotAfter:     time.Now().Add(time.Hour * 24 * 365 * 100),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  cfg.Usages,
	}
	certDERBytes, err := x509.CreateCertificate(cryptorand.Reader, &certTmpl, caCert, clientKey, caKey)
	if err != nil {
		return nil, err
	}
	return certDERBytes, err
	//return x509.ParseCertificate(certDERBytes)
}


// NewSelfSignedCACert creates a CA certificate
//func NewSelfSignedCACert(key crypto.Signer) (*x509.Certificate, error) {
//	tmpl := x509.Certificate{
//		SerialNumber: big.NewInt(1024),
//		Subject: pkix.Name{
//			CommonName: "HUAWEI",
//		},
//		NotBefore: time.Now(),
//		NotAfter:  time.Now().Add(time.Hour * 24 * 365 * 100),
//
//		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
//		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
//		BasicConstraintsValid: true,
//		IsCA:                  true,
//	}
//
//	certDERBytes, err := x509.CreateCertificate(cryptorand.Reader, &tmpl, &tmpl, key.Public(), key)
//	if err != nil {
//		return nil, err
//	}
//	return x509.ParseCertificate(certDERBytes)
//}


//func generateCA(host string) ([]byte, []byte, error){
//	rootKey, err := rsa.GenerateKey(cryptorand.Reader, 2048)//CAkey
//	if err != nil {
//		return nil, nil, err
//	}
//	//生成CA
//	CAtemplate := x509.Certificate{
//		SerialNumber: big.NewInt(1024),
//		Subject: pkix.Name{
//			CommonName: fmt.Sprintf("%s@%d", host, time.Now().Unix()),
//		},
//		NotBefore: time.Now(),
//		NotAfter:  time.Now().Add(time.Hour * 24 * 365 * 100),
//
//		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
//		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
//		BasicConstraintsValid: true,
//		IsCA:                  true,
//	}
//	//自签证书
//	derBytes, err := x509.CreateCertificate(cryptorand.Reader, &CAtemplate, &CAtemplate, &rootKey.PublicKey, rootKey)
//	if err != nil {
//		return nil, nil, err
//	}
//	//caOut, _:=os.Create("cacert.pem")
//	//pem.Encode(caOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
//	//caOut.Close()
//
//	//Generate cert
//	certBuffer := bytes.Buffer{}
//	pem.Encode(&certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
//
//	// Generate key
//	keyBuffer := bytes.Buffer{}
//	pem.Encode(&keyBuffer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rootKey)})
//	//keyOut, _:=os.Create("key.pem")
//	//pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rootKey)})
//	//keyOut.Close()
//
//	return certBuffer.Bytes(), keyBuffer.Bytes(), nil
//}
//
//func CreateCertFiles(certFileName, keyFileName string, host string) (err error) {
//	if _, err := os.Stat(certFileName); err == nil {
//		if _, err := os.Stat(keyFileName); err == nil {
//			return nil
//		}
//	}
//
//	certPem, keyPem, err := generateCA(host)
//	if err != nil {
//		return err
//	}
//
//	os.MkdirAll(filepath.Dir(certFileName), os.FileMode(0777))
//	err = ioutil.WriteFile(certFileName, certPem, os.FileMode(0777))
//	if err != nil {
//		return err
//	}
//
//	os.MkdirAll(filepath.Dir(keyFileName), os.FileMode(0777))
//	err = ioutil.WriteFile(keyFileName, keyPem, os.FileMode(0777))
//	if err != nil {
//		return err
//	}
//
//	return nil
//}





//// NewSelfSignedCACert creates a CA certificate
//func NewSelfSignedCACert(key crypto.Signer, commonName string, organization []string) (*x509.Certificate, error) {
//	now := time.Now()
//	tmpl := x509.Certificate{
//		SerialNumber: new(big.Int).SetInt64(0),
//		Subject: pkix.Name{
//			CommonName:   commonName,
//			Organization: organization,
//		},
//		NotBefore:             now.UTC(),
//		NotAfter:              now.Add(time.Hour * 24 * 365 * 100),
//		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
//		BasicConstraintsValid: true,
//		IsCA:                  true,
//	}
//
//	certDERBytes, _ := x509.CreateCertificate(cryptorand.Reader, &tmpl, &tmpl, key.Public(), key)
//	return x509.ParseCertificate(certDERBytes)
//}
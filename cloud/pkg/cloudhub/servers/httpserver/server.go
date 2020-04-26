/*
Copyright 2020 The KubeEdge Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package httpserver

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/klog"
)

// StartHttpServer starts the http service
func StartHttpServer() {
	router := mux.NewRouter()
	router.HandleFunc("/edge.crt", edgeCoreClientCert).Methods("GET")
	//router.HandleFunc("/client.crt", edgeCoreClientCert).Methods("GET")
	router.HandleFunc("/ca.crt", getCA).Methods("GET")

	klog.Fatal(http.ListenAndServeTLS(":3000", "", "", router))
}
//done
func getCA(w http.ResponseWriter, r *http.Request) {
	caCertDER,_,_:= generateCaIfnotExist()
	w.Write(caCertDER)	//w.Write([]byte(fmt.Sprintf("CA will be returned")))

}

//edgeCoreClientCert will verify the token then create edgeCoreCert and return it
func edgeCoreClientCert(w http.ResponseWriter, r *http.Request) {
	authorizationHeader := r.Header.Get("authorization")
	if authorizationHeader == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf("Invalid authorization token")))
		return
	}
	bearerToken := strings.Split(authorizationHeader, " ")
	if len(bearerToken) != 2 {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf("Invalid authorization token")))
		return
	}
	token, err := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		//TODO:私钥 方法 byteToken转换成jwt.token
		return []byte("cakey"), nil//ca的key
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(fmt.Sprintf("Invalid authorization token")))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("Invalid authorization token")))
		return
	}
	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf("Invalid authorization token")))
		return
	}

	csrContent, _ := ioutil.ReadAll(r.Body)
	csr,_:=x509.ParseCertificateRequest(csrContent)
	subject:=csr.Subject
	// sign the certs using CA and return to edge
	clientCertDER, err := signCerts(subject, csr.PublicKey)
	w.Write(clientCertDER)
	//w.Write([]byte(fmt.Sprintf("Will return the certs for edgecore")))
}

//func signCerts(subInfo pkix.Name,csr crypto.PublicKey) (*x509.Certificate, error){
func signCerts(subInfo pkix.Name,pbKey crypto.PublicKey) ([]byte, error){
	cfgs := &certutil.Config{
		CommonName:   subInfo.CommonName,
		Organization: subInfo.Organization,
		Usages:       nil,
	}
	clientKey:= pbKey

	_,caCert,caKey:= generateCaIfnotExist()

	//creates a signed certificate using the given CA certificate and key
	//certDER就是x509.CreateCertificate的返回值,是二进制的
	certDER, _ :=NewCertFromCA(cfgs,caCert,clientKey,caKey)
	return certDER,nil
}


func checkCAExists() (exist bool,err error){
	//TODO:从本地
	Secret, err := GetSecret(CaSecretName)
	if Secret!=nil{
		return true,err
	}
	return false,err
}
func checkCloudCoreCertExists() (exist bool,err error){
	Secret, err := GetSecret(CloudCoreSecretName)
	if Secret!=nil{
		return true,err
	}
	return false,err
}
//本地 SECRET
func generateCaIfnotExist()([]byte,*x509.Certificate,crypto.Signer){
	//Check if the certificate exists
	isExist,_:=checkCAExists()
	var caCert  *x509.Certificate
	var caDER []byte
	var caKey crypto.Signer
	if isExist==true{
		caSecret,err:=GetSecret(CaSecretName)
		if err != nil {
			fmt.Println("can't find ca!")
		}
		caDER=caSecret.Data[CaDataName]
		caKeyDer:=caSecret.Data[CaKeyDataName]
		caKey, err =x509.ParsePKCS1PrivateKey(caKeyDer)
		if err != nil {
			fmt.Println("wrong!")
		}
		caCert, _ =x509.ParseCertificate(caDER)
	}else{
		//Create CA then return cacert and ca key
		caDER,caKey,_=NewCertificateAuthorityDer()
		caKey := x509.MarshalPKCS1PrivateKey(caKey.(*rsa.PrivateKey))
		//save to etcd
		CreateCaSecret(caDER,caKey)
		//caCert,err:=x509.ParseCertificate(caDER)
		//WriteCertAndKey("/etc/kubeedge/ca/" , "rootCa" ,caCert,key)
	}
	caCert, _ =x509.ParseCertificate(caDER)
	return caDER,caCert,caKey
}


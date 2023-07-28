package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func readPrivateKeyFromFile(filePath string) (*rsa.PrivateKey, error) {
	keyBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("Failed To Parse PEM block containing the key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Invalid Private Key Type")
	}

	return rsaPrivateKey, nil
}

func createSignature(privateKey *rsa.PrivateKey, data string) (string, error) {
	hashed := sha256.Sum256([]byte(data))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}

	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	return signatureBase64, nil
}

func main() {

	privateKeyFilePath := "private_key.pem"

	dataToSign := "merchant_code=BEANBAKERY&account_number=M686376800000007"

	privateKey, err := readPrivateKeyFromFile(privateKeyFilePath)
	if err != nil {
		fmt.Println("Error Read PrivateKey:", err)
		return
	}

	signature, err := createSignature(privateKey, dataToSign)
	if err != nil {
		fmt.Println("Error Create Signature:", err)
		return
	}

	fmt.Println("Signature is:", signature)
}

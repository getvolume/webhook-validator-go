package validator

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

var logger = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime)

type Validator struct {
	pemUrl string
}

func New(pemUrl string) Validator {
	v := Validator{
		pemUrl: pemUrl,
	}
	return v
}

type ValidationResponse struct {
	IsValid bool
	Errors  []string
}

func (v Validator) Run(payload string, signature string) ValidationResponse {


	var errors []string

	verification, err := verifySignature(v.pemUrl, signature, payload)
	if err != nil || !verification {
		errors = append(errors, "Signature not valid")
	}

	var data map[string]string
	err = json.Unmarshal([]byte(payload), &data)

	paymentID, idOk := data["paymentId"]
	if !idOk || paymentID == "" {
		errors = append(errors, `Invalid or missing "paymentId" field`)
	}

	paymentStatus, statusOk := data["paymentStatus"]
	if !statusOk || paymentStatus == "" {
		errors = append(errors, `Invalid or missing "paymentStatus" field`)
	}

	// ... validate other payments according to business logic

	if len(errors) > 0 {
		return ValidationResponse{
			IsValid: false,
			Errors:  errors,
		}
	}

	return ValidationResponse{
		IsValid: true,
	}
}

func verifySignature(pemUrl string, signature string, payload string) (bool, error) {
	pubKey, err := fetchPublicKey(pemUrl)
	if err != nil {
		return false, err
	}

	decodedSig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}

	hashed := sha256.Sum256([]byte(payload))
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], decodedSig)
	if err != nil {
		return false, err
	}

	return true, nil
}

func fetchPublicKey(pemurl string) (*rsa.PublicKey, error) {
	resp, err := http.Get(pemurl)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Add prefix and postfix to the fetched data
	fullPEM := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", body)
	block, _ := pem.Decode([]byte(fullPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not RSA public key")
	}

	return rsaPub, nil
}

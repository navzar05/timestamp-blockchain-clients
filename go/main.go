package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/hash"
	"github.com/joho/godotenv"
)

type Document struct {
	SerialNumber string `json:"serial_number"`
	Hash         string `json:"hash"`
}

// CMS (Cryptographic Message Syntax) structures
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type SignerIdentifier struct {
	IssuerAndSerialNumber IssuerAndSerialNumber
}

type SignerInfo struct {
	Version            int
	Sid                asn1.RawValue
	DigestAlgorithm    pkixAlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkixAlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type EncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type SignedData struct {
	Version          int
	DigestAlgorithms []pkixAlgorithmIdentifier `asn1:"set"`
	EncapContentInfo EncapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	Crls             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []SignerInfo  `asn1:"set"`
}

func makeTimestampRequest(data []byte, nonce *big.Int) ([]byte, error) {
	h := sha256.Sum256(data)

	oidSHA256 := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

	mi := MessageImprint{
		HashAlgorithm: pkixAlgorithmIdentifier{
			Algorithm: oidSHA256,
		},
		HashedMessage: h[:],
	}

	req := TimeStampReq{
		Version:        1,
		MessageImprint: mi,
		Nonce:          nonce,
		CertReq:        true,
	}

	der, err := asn1.Marshal(req)
	if err != nil {
		return nil, err
	}
	return der, nil
}

func sendTimestampRequest(tsaURL string, reqDER []byte) ([]byte, error) {
	client := &http.Client{Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}}
	httpReq, err := http.NewRequest("POST", tsaURL, bytes.NewReader(reqDER))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/timestamp-query")
	httpReq.Header.Set("Accept", "application/timestamp-reply")

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("TSA responded status %d: %s", resp.StatusCode, string(body))
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return respBytes, nil
}

func parseTimestampResponse(respDER []byte) (*TimeStampResp, error) {
	var resp TimeStampResp
	rest, err := asn1.Unmarshal(respDER, &resp)
	if err != nil {
		return nil, fmt.Errorf("unmarshal response failed: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("trailing bytes after TimeStampResp")
	}
	if !(resp.Status.Status == 0 || resp.Status.Status == 1) {
		return nil, fmt.Errorf("TSA returned failure: status %d", resp.Status.Status)
	}
	return &resp, nil
}

var tsaURL = envOrDefault("TSA_URL", "http://localhost:3000/api/v1/timestamp")

func postDocument(c *gin.Context) {
	file, _ := c.FormFile("document")

	log.Println(file.Filename)

	openedFile, err := file.Open()
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to open file")
		return
	}
	defer openedFile.Close()

	content, err := io.ReadAll(openedFile)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to read file")
		return
	}

	nonce := big.NewInt(123456789)

	reqDER, err := makeTimestampRequest(content, nonce)
	if err != nil {
		panic("make request: " + err.Error())
	}
	fmt.Printf("Request DER (hex): %s\n", hex.EncodeToString(reqDER))

	rspBytes, err := sendTimestampRequest(tsaURL, reqDER)
	if err != nil {
		panic("send request: " + err.Error())
	}
	fmt.Printf("Response DER length: %d bytes\n", len(rspBytes))

	resp, err := parseTimestampResponse(rspBytes)
	if err != nil {
		panic("parse response: " + err.Error())
	}
	fmt.Println("Parsed response. Token raw bytes length:", len(resp.TimeStampToken.FullBytes))

	tstFilename := file.Filename + ".tst"
	c.Header("Content-Disposition", "attachment; filename=\""+tstFilename+"\"")
	c.Data(http.StatusOK, "application/timestamp-reply", rspBytes)
}

func postToken(c *gin.Context) {
	file, err := c.FormFile("token")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token file is required"})
		return
	}

	log.Println("Received token file:", file.Filename)

	openedFile, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open token file"})
		return
	}
	defer openedFile.Close()

	tokenBytes, err := io.ReadAll(openedFile)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read token file"})
		return
	}

	var tokenDER []byte

	var resp TimeStampResp
	_, err = asn1.Unmarshal(tokenBytes, &resp)
	if err == nil && (resp.Status.Status == 0 || resp.Status.Status == 1) {
		tokenDER = resp.TimeStampToken.FullBytes
		if len(tokenDER) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Empty timestamp token in response"})
			return
		}
	} else {
		tokenDER = tokenBytes
	}

	var contentInfo ContentInfo
	_, err = asn1.Unmarshal(tokenDER, &contentInfo)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse ContentInfo: " + err.Error()})
		return
	}
	var signedData SignedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &signedData)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse SignedData: " + err.Error()})
		return
	}

	var tstInfoBytes []byte
	_, err = asn1.Unmarshal(signedData.EncapContentInfo.EContent.Bytes, &tstInfoBytes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to extract TSTInfo bytes: " + err.Error()})
		return
	}

	var tstInfo TSTInfo
	_, err = asn1.Unmarshal(tstInfoBytes, &tstInfo)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse TSTInfo: " + err.Error()})
		return
	}

	serialNumber := tstInfo.SerialNumber.String()
	fmt.Printf("Extracted serial number: %s\n", serialNumber)

	valid, err := verifyOnHyperledger(serialNumber, tokenBytes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"valid":        false,
			"error":        err.Error(),
			"serialNumber": serialNumber,
		})
		return
	}

	if !valid {
		c.JSON(http.StatusOK, gin.H{
			"valid":        false,
			"message":      "Token verification failed",
			"serialNumber": serialNumber,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":        true,
		"message":      "Token verified successfully",
		"serialNumber": serialNumber,
	})
}

func initServer() {
	godotenv.Load()
}

func verifyOnHyperledger(serialNumber string, rawToken []byte) (bool, error) {
	fmt.Printf("verifyOnHyperledger called with SN: %s\n", serialNumber)

	// Create connection
	clientConnection := newGrpcConnection()
	defer clientConnection.Close()

	gw, err := client.Connect(
		newIdentity(),
		client.WithSign(newSign()),
		client.WithHash(hash.SHA256),
		client.WithClientConnection(clientConnection),
	)
	if err != nil {
		return false, fmt.Errorf("failed to connect: %w", err)
	}
	defer gw.Close()

	network := gw.GetNetwork(channelName)
	contract := network.GetContract(chaincodeName)

	fmt.Printf("Calling EvaluateTransaction for serial number: %s\n", serialNumber)
	rsp, err := contract.EvaluateTransaction("VerifyDocument", serialNumber)
	if err != nil {
		fmt.Printf("Error evaluating transaction: %v\n", err)
		return false, fmt.Errorf("failed to verify document: %w", err)
	}

	fmt.Printf("Response from blockchain: %s\n", string(rsp))

	var document Document
	if err := json.Unmarshal(rsp, &document); err != nil {
		fmt.Printf("Error unmarshaling response: %v\n", err)
		return false, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Verify the hash matches
	currentHash := sha256.Sum256(rawToken)
	currentHashString := hex.EncodeToString(currentHash[:])

	fmt.Printf("Stored hash from blockchain: %s\n", document.Hash)
	fmt.Printf("Current timestamp hash: %s\n", currentHashString)

	if document.Hash != currentHashString {
		return false, fmt.Errorf("hash mismatch: stored=%s, current=%s", document.Hash, currentHashString)
	}

	return true, nil
}

func main() {
	initServer()

	router := gin.Default()

	router.MaxMultipartMemory = 200 << 20

	router.POST("/upload", postDocument)
	router.POST("/verify", postToken)

	router.Run(":8080")
}

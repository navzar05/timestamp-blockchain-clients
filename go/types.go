package main

import (
	"encoding/asn1"
	"math/big"
	"time"
)

type pkixAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type MessageImprint struct {
	HashAlgorithm pkixAlgorithmIdentifier
	HashedMessage []byte
}

type TimeStampReq struct {
	Version        int
	MessageImprint MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     asn1.RawValue         `asn1:"explicit,tag:0,optional"`
}

type PKIStatusInfo struct {
	Status       int
	FailureInfo  asn1.BitString `asn1:"optional"`
	StatusString []string       `asn1:"optional"`
}

type TimeStampResp struct {
	Status         PKIStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

type TSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time
	Accuracy       asn1.RawValue `asn1:"optional"`
	Ordering       bool          `asn1:"optional,default:false"`
	Nonce          *big.Int      `asn1:"optional"`
	Tsa            asn1.RawValue `asn1:"tag:0,optional,explicit"`
	Extensions     asn1.RawValue `asn1:"tag:1,optional,implicit"`
}

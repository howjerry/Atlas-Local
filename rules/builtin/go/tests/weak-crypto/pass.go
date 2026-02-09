// Weak Crypto: should NOT trigger the rule
// Uses SHA-256 for hashing

package main

import "crypto/sha256"

func hashWithSHA256(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

func quickSHA256(data []byte) [32]byte {
	return sha256.Sum256(data)
}

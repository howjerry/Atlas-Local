// Insecure Random: should NOT trigger the rule
// Uses crypto/rand for secure random number generation

package main

import (
	"crypto/rand"
	"math/big"
)

func generateSecureToken() (*big.Int, error) {
	max := big.NewInt(1000000)
	return rand.Int(rand.Reader, max)
}

func secureRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

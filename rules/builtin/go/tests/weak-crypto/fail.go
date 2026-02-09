// Weak Crypto: SHOULD trigger the rule
// Pattern: Using MD5 or SHA1 hash functions
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

package main

import (
	"crypto/md5"
	"crypto/sha1"
)

func hashWithMD5(data []byte) []byte {
	h := md5.New()
	h.Write(data)
	return h.Sum(nil)
}

func hashWithSHA1(data []byte) [20]byte {
	return sha1.Sum(data)
}

func quickMD5(data []byte) [16]byte {
	return md5.Sum(data)
}

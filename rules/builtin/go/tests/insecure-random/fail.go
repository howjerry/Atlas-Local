// Insecure Random: SHOULD trigger the rule
// Pattern: Using math/rand for random number generation
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

package main

import "math/rand"

func generateToken() int {
	return rand.Intn(1000000)
}

func randomFloat() float64 {
	return rand.Float64()
}

func shuffleItems(items []int) {
	rand.Shuffle(len(items), func(i, j int) {
		items[i], items[j] = items[j], items[i]
	})
}

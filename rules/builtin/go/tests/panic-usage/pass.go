// Panic Usage: should NOT trigger the rule
// Returns errors instead of panicking

package main

import (
	"errors"
	"fmt"
)

func processData(data []byte) error {
	if len(data) == 0 {
		return errors.New("data cannot be empty")
	}
	return nil
}

func divide(a, b int) (int, error) {
	if b == 0 {
		return 0, fmt.Errorf("division by zero: %d / %d", a, b)
	}
	return a / b, nil
}

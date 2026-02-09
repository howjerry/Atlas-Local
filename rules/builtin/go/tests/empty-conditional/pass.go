// Empty Conditional: should NOT trigger the rule
// All if blocks have meaningful bodies

package main

import "fmt"

func checkValue(x int) {
	if x > 0 {
		fmt.Println("positive")
	}

	if x == 42 {
		return
	}
}

func validate(name string) {
	if len(name) > 100 {
		name = name[:100]
	}
	_ = name
}

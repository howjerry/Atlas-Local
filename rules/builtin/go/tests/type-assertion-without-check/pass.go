// Type Assertion Without Check: should NOT trigger the rule
// Uses comma-ok form or type switch for safe type assertion

package main

import "fmt"

func processInterface(val interface{}) {
	if s, ok := val.(string); ok {
		fmt.Println(s)
	}
}

func handleValue(v interface{}) {
	switch v := v.(type) {
	case int:
		fmt.Println(v)
	case string:
		fmt.Println(v)
	}
}

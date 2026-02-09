// Empty Conditional: SHOULD trigger the rule
// Pattern: if statements with empty bodies

package main

func checkValue(x int) {
	if x > 0 { }

	if x == 42 { }
}

func validate(name string) {
	if len(name) > 100 { }
}

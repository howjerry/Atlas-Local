// Type Assertion Without Check: SHOULD trigger the rule
// Pattern: Type assertion in expression statement without comma-ok form

package main

func processInterface(val interface{}) {
	val.(string)
}

func handleValue(v interface{}) {
	v.(int)
}

func castAndDiscard(x interface{}) {
	x.(float64)
}

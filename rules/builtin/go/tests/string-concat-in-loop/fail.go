// String Concatenation in Loop: SHOULD trigger the rule
// Pattern: Using += with string concatenation via + inside for loops

package main

func buildMessage(items []string) string {
	result := ""
	for i := 0; i < len(items); i++ {
		result = result + items[i]
	}
	return result
}

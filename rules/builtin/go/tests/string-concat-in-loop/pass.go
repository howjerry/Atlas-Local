// String Concatenation in Loop: should NOT trigger the rule
// Uses strings.Builder for efficient string construction

package main

import "strings"

func buildMessage(items []string) string {
	var sb strings.Builder
	for _, item := range items {
		sb.WriteString(item)
	}
	return sb.String()
}

func joinItems(items []string) string {
	return strings.Join(items, ", ")
}

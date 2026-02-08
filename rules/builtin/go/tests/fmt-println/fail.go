package main

import "fmt"

func debugOutput(value string) {
	fmt.Println("Debug:", value)
	fmt.Printf("Processing: %s\n", value)
	fmt.Print("done\n")
}

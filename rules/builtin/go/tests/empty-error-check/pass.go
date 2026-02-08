package main

import "fmt"

func processFile(path string) error {
	data, err := readFile(path)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", path, err)
	}
	_ = data
	return nil
}

func readFile(path string) ([]byte, error) {
	return nil, nil
}

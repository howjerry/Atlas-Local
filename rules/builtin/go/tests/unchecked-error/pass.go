package main

import (
	"fmt"
	"os"
)

func removeFile(path string) error {
	err := os.Remove(path)
	if err != nil {
		return fmt.Errorf("failed to remove %s: %w", path, err)
	}
	return nil
}

func writeData(w *os.File, data string) error {
	n, err := fmt.Fprintf(w, "data: %s", data)
	if err != nil {
		return err
	}
	_ = n
	return nil
}

func closeFile(f *os.File) error {
	if err := f.Close(); err != nil {
		return err
	}
	return nil
}

package main

import "os"

func processFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return nil
}

func processFiles(paths []string) {
	for _, path := range paths {
		_ = processFile(path)
	}
}

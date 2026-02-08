package main

import "os"

func processFiles(paths []string) {
	for _, path := range paths {
		f, _ := os.Open(path)
		defer f.Close()
		_ = f
	}
}

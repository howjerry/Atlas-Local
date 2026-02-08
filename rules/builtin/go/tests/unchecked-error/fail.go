package main

import (
	"fmt"
	"os"
)

func removeFile(path string) {
	_ = os.Remove(path)
}

func writeData(w *os.File, data string) {
	_, _ = fmt.Fprintf(w, "data: %s", data)
}

func closeFile(f *os.File) {
	_ = f.Close()
}

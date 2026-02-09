package main

import (
	"io/ioutil"
	"net/http"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	filename := r.FormValue("file")
	safe := filepath.Base(filename)
	ioutil.ReadFile(safe)
}

package main

import (
	"io/ioutil"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	path := r.FormValue("path")
	ioutil.ReadFile(path)
}

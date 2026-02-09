package main

import (
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	url := r.FormValue("url")
	http.Get(url)
}

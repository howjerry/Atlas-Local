package main

import (
	"fmt"
	"html"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	safe := html.EscapeString(name)
	fmt.Fprintf(w, safe)
}

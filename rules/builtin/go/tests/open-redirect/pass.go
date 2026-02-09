// Open Redirect: should NOT trigger the rule
// Uses hardcoded redirect paths (not http.Redirect calls)

package main

import "net/http"

func handleSafeRedirect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Location", "/dashboard")
	w.WriteHeader(http.StatusFound)
}

func serveHome(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome"))
}

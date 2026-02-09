// Open Redirect: SHOULD trigger the rule
// Pattern: http.Redirect with potentially user-controlled URL
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

package main

import "net/http"

func handleRedirect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	http.Redirect(w, r, target, http.StatusFound)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	returnURL := r.FormValue("return_to")
	http.Redirect(w, r, returnURL, http.StatusSeeOther)
}

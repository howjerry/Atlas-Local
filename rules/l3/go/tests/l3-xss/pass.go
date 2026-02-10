// L3 XSS (safe): 經過 html.EscapeString 淨化
package main

func handleSearch(w http.ResponseWriter, r *http.Request) {
	query := html.EscapeString(r.FormValue("q"))
	renderResult(w, query)
}

func renderResult(w http.ResponseWriter, content string) {
	fmt.Fprintf(w, "<h1>"+content+"</h1>")
}

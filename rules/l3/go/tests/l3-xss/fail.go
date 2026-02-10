// L3 XSS: 跨函數污染 — r.FormValue → arg → fmt.Fprintf
// 注意：此為 SAST 偵測用測試夾具
package main

func handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.FormValue("q")
	renderResult(w, query)
}

func renderResult(w http.ResponseWriter, content string) {
	fmt.Fprintf(w, "<h1>"+content+"</h1>")
}

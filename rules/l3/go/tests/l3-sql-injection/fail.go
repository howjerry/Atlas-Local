// L3 SQL Injection: 跨函數污染 — r.FormValue → arg → db.Query
// 注意：此為 SAST 偵測用測試夾具
package main

func handleSearch(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	queryUser(name)
}

func queryUser(username string) {
	sql := "SELECT * FROM users WHERE name = '" + username + "'"
	db.Query(sql)
}

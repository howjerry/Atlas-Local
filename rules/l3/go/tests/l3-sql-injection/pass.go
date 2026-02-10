// L3 SQL Injection (safe): 經過 strconv.Atoi 淨化
package main

func handleSearch(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.FormValue("id"))
	queryUser(id)
}

func queryUser(userId int) {
	sql := "SELECT * FROM users WHERE id = " + strconv.Itoa(userId)
	db.Query(sql)
}

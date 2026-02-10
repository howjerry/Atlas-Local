// Template Injection: should NOT trigger the rule
// 使用硬編碼的模板字串

package main

import (
	"html/template"
	"net/http"
)

func safeTemplate(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")

	// 安全：使用硬編碼的模板
	t, _ := template.New("page").Parse("<h1>Hello {{.Name}}</h1>")
	t.Execute(w, map[string]string{"Name": name})
}

func safeParseFiles(w http.ResponseWriter) {
	// 安全：從已知檔案載入模板
	t, _ := template.ParseFiles("templates/index.html")
	t.Execute(w, nil)
}


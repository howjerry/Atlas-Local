// Template Injection: SHOULD trigger the rule
// Pattern: template.Parse 使用變數作為模板內容
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

package main

import (
	"html/template"
	"net/http"
)

func unsafeTemplate(w http.ResponseWriter, r *http.Request) {
	userTemplate := r.FormValue("template")

	// 不安全：Parse 使用變數
	t, _ := template.New("page").Parse(userTemplate)
	t.Execute(w, nil)
}

func unsafeGlob(pattern string) {
	// 不安全：ParseGlob 使用變數
	t, _ := template.New("").ParseGlob(pattern)
	_ = t
}


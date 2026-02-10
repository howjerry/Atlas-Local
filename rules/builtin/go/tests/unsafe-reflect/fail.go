// Unsafe Reflect: SHOULD trigger the rule
// Pattern: reflect 使用變數作為方法名或欄位名
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

package main

import (
	"net/http"
	"reflect"
)

type Service struct{}

func (s *Service) GetUser()  {}
func (s *Service) DeleteAll() {}

func unsafeMethodByName(r *http.Request) {
	methodName := r.FormValue("method")
	svc := &Service{}
	v := reflect.ValueOf(svc)
	// 不安全：使用使用者輸入的方法名
	m := v.MethodByName(methodName)
	m.Call(nil)
}

func unsafeFieldByName(r *http.Request) {
	fieldName := r.FormValue("field")
	svc := &Service{}
	v := reflect.ValueOf(svc).Elem()
	// 不安全：使用使用者輸入的欄位名
	f := v.FieldByName(fieldName)
	_ = f
}


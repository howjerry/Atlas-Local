// Unsafe Reflect: should NOT trigger the rule
// 使用硬編碼字串或 allowlist 進行 reflection

package main

import "reflect"

type SafeService struct {
	Name string
}

func safeMethodByName() {
	svc := &SafeService{}
	v := reflect.ValueOf(svc)
	// 安全：使用硬編碼字串
	m := v.MethodByName("String")
	_ = m
}

func safeWithAllowlist(input string) {
	allowed := map[string]bool{"Get": true, "List": true}
	if !allowed[input] {
		return
	}
	// 安全：經過 allowlist 驗證後才使用
}


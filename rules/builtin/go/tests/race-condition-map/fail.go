// Race Condition Map: SHOULD trigger the rule
// Pattern: goroutine 中直接存取 map 沒有同步機制
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

package main

func unsafeConcurrentMap() {
	m := make(map[string]int)

	// 不安全：goroutine 中直接讀寫 map
	go func() {
		m["key"] = 42
	}()

	go func() {
		_ = m["key"]
	}()
}


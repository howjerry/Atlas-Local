// Race Condition Map: should NOT trigger the rule
// 使用 sync.Map 或 sync.Mutex 保護 map 存取

package main

import "sync"

func safeSyncMap() {
	var m sync.Map

	// 安全：使用 sync.Map
	go func() {
		m.Store("key", 42)
	}()

	go func() {
		val, _ := m.Load("key")
		_ = val
	}()
}

func safeMutexMap() {
	m := make(map[string]int)
	var mu sync.RWMutex

	// 安全：使用 RWMutex 保護
	go func() {
		mu.Lock()
		m["key"] = 42
		mu.Unlock()
	}()
}


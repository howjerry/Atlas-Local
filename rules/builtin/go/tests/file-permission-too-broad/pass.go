// File Permission Too Broad: should NOT trigger the rule
// 使用適當的最小權限

package main

import "os"

func safeOpenFile() {
	// 安全：0600 僅擁有者可讀寫
	f, _ := os.OpenFile("data.txt", os.O_CREATE|os.O_WRONLY, 0600)
	f.Close()
}

func safeChmod() {
	// 安全：0644 擁有者可讀寫，其他僅可讀
	os.Chmod("config.yaml", 0644)
}

func safeMkdirAll() {
	// 安全：0755 目錄標準權限
	os.MkdirAll("/tmp/data", 0755)
}

func safeWriteFile() {
	// 安全：0600 僅擁有者可讀寫
	os.WriteFile("output.txt", []byte("data"), 0600)
}


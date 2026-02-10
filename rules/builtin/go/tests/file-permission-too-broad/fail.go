// File Permission Too Broad: SHOULD trigger the rule
// Pattern: os.OpenFile/Chmod 使用過於寬鬆的權限
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

package main

import "os"

func unsafeOpenFile() {
	// 不安全：0777 所有人都可讀寫執行
	f, _ := os.OpenFile("data.txt", os.O_CREATE|os.O_WRONLY, 0777)
	f.Close()
}

func unsafeChmod() {
	// 不安全：0666 所有人都可讀寫
	os.Chmod("config.yaml", 0666)
}

func unsafeMkdirAll() {
	// 不安全：0777 目錄權限過寬
	os.MkdirAll("/tmp/data", 0777)
}

func unsafeWriteFile() {
	// 不安全：0766 group 和 other 可讀寫
	os.WriteFile("output.txt", []byte("data"), 0766)
}


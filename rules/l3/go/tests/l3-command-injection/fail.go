// L3 Command Injection: 跨函數污染 — r.FormValue → arg → exec.Command
// 注意：此為 SAST 偵測用測試夾具
package main

func handleAction(w http.ResponseWriter, r *http.Request) {
	cmd := r.FormValue("cmd")
	runTask(cmd)
}

func runTask(command string) {
	exec.Command(command)
}

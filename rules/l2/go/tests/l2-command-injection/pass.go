package main

import (
	"fmt"
	"net/http"
	"strconv"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.FormValue("cmd")
	safe, _ := strconv.Atoi(cmd)
	fmt.Println(safe)
}

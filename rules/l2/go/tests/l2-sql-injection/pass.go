package main

import (
	"fmt"
	"net/http"
	"strconv"
)

func handler(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	safeId, _ := strconv.Atoi(id)
	fmt.Println(safeId)
}

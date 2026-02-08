package main

import "log"

func properLogging(value string) {
	log.Printf("Processing: %s", value)
}

func processData(data string) string {
	return data + " processed"
}

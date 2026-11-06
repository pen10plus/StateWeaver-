package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/stateweaver/stateweaver/lab/api"
)

func main() {
	port := flag.Int("port", 8081, "Port for secure API")
	flag.Parse()

	srv := api.NewLabServer(*port, true)
	fmt.Printf("[+] StateWeaver Secure Lab API listening on http://127.0.0.1:%d\n", *port)
	if err := srv.Start(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}


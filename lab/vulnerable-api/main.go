package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/stateweaver/stateweaver/lab/api"
)

func main() {
	port := flag.Int("port", 8080, "Port for vulnerable API")
	flag.Parse()

	srv := api.NewLabServer(*port, false)
	fmt.Printf("[+] StateWeaver Vulnerable Lab API listening on http://127.0.0.1:%d\n", *port)
	if err := srv.Start(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}


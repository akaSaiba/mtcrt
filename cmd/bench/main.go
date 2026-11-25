// Command bench runs the benchmarks described by a JSON config.
package main

import (
	"fmt"
	"log"
	"os"

	"mtcrt/bench"
	"mtcrt/bench/config"
)

// Loads config and runs benchmarks.
func main() {
	log.SetFlags(0)
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./cmd/bench <config.json>")
		os.Exit(2)
	}

	path := os.Args[1]
	cfg, raw, err := config.Load(path)
	if err != nil {
		log.Fatal(err)
	}

	count, err := cfg.Count()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Fprintf(os.Stderr, "%d configurations\n", count)
	if err := bench.Run(cfg, path, raw, func(message string) {
		fmt.Fprintln(os.Stderr, message)
	}); err != nil {
		log.Fatal(err)
	}
}

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/atpons/39ac/pcaptool/pkg/raw"
)

var (
	dev = flag.String("dev", "lo", "network interface")
)

func main() {
	flag.Parse()

	sock, err := raw.NewSocket()
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}

	sock.Start(*dev)
}

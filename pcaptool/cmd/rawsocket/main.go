package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/atpons/39ac/pcaptool/pkg/raw"
)

var (
	dev       = flag.String("dev", "lo", "network interface")
	bridgeDev = flag.String("brdev", "", "bridge network interface")
)

func main() {
	flag.Parse()

	log.Printf("dev=%s, bridgeDev=%s", *dev, *bridgeDev)

	//sock, err := raw.NewSocket(*dev, raw.OptionBridge(*bridgeDev))
	sock, err := raw.NewSocket(*dev)
	defer sock.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}

	if err := sock.Start(); err != nil {
		panic(err)
	}
}

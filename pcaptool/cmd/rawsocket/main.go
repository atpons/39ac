package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/atpons/39ac/pcaptool/pkg/raw"
)

var (
	dev       = flag.String("dev", "lo", "network interface")
	bridgeDev = flag.String("brdev", "lo", "bridge network interface")
)

func main() {
	flag.Parse()

	sock, err := raw.NewSocket(*dev, raw.OptionBridge(*bridgeDev))
	defer sock.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}

	//go func() {
	if err := sock.Start(); err != nil {
		panic(err)
	}
	//}()

	//bridgeSock, err := raw.NewSocket(*bridgeDev, raw.OptionBridge(*dev))
	//defer bridgeSock.Close()
	//
	//if err := bridgeSock.Start(); err != nil {
	//	panic(err)
	//}
}

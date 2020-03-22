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

var (
	nextHop = [8]byte{0x00, 0x0c, 0x29, 0x9d, 0x40, 0x26, 0x00, 0x00}
)

func main() {
	flag.Parse()

	copy(nextHop[0:7], nextHop[0:7])

	log.Printf("dev=%s, bridgeDev=%s", *dev, *bridgeDev)

	sock, err := raw.NewSocket(*dev, raw.OptionBridge(*bridgeDev), raw.OptionNextHop(nextHop))
	//sock, err := raw.NewSocket(*dev)
	defer sock.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}

	brSock, err := raw.NewSocket(*bridgeDev, raw.OptionBridge(*dev), raw.OptionNextHop(nextHop))
	defer brSock.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}
	go brSock.Start(brSock.Fd, brSock.Dev, sock.ScanSocket)

	if err := sock.Start(sock.Fd, sock.Dev, sock.ScanSocket); err != nil {
		panic(err)
	}
}

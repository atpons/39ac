package main

import (
	"os"

	"github.com/atpons/39ac/pcaptool/pkg/pcap"
)

func main() {
	p := pcap.Read(os.Getenv("PCAP_FILE"))
	p.Print()
}

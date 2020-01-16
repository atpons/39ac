package pcap

import (
	"fmt"
	"os"

	"golang.org/x/net/icmp"
)

type ICMP icmp.Message

func (i ICMP) Print() {
	fmt.Fprintf(os.Stdout, "[ICMP] Type=%d, Code=%#x, Checksum=%#x, Body=%#x\n", i.Type, i.Code, i.Checksum, i.Body)
}

func (i ICMP) Bytes() []byte {
	ic := icmp.Message(i)
	b, _ := ic.Marshal(nil)
	return b
}

func ReadICMP(len int, data []byte) ICMP {
	fmt.Fprintf(os.Stderr, "** Remain Data: %d\n", len)
	fmt.Fprintf(os.Stdout, "%#x", data)
	icmpData, err := icmp.ParseMessage(ProtocolICMP, data)
	if err != nil {
		panic(err)
	}
	return ICMP(*icmpData)
}

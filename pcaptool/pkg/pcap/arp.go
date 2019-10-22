package pcap

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

type Arp struct {
	Htype     []byte
	Ptype     []byte
	Hlen      []byte
	Plen      []byte
	Op        []byte
	SenderMac []byte
	SenderIP  []byte
	TargetMac []byte
	TargetIP  []byte
}

func ReadArp(len int, buf *bufio.Reader) Arp {
	fmt.Fprintf(os.Stderr, "Remain Byte: %d\n", len)
	data := make([]byte, len)
	io.ReadFull(buf, data)
	arp := Arp{}
	arp.Htype = data[0:2]
	arp.Ptype = data[2:4]
	arp.Hlen = data[4:5]
	arp.Plen = data[5:6]
	arp.Op = data[6:8]
	arp.SenderMac = data[8:14]
	arp.SenderIP = data[14:18]
	arp.TargetMac = data[18:23]
	arp.TargetIP = data[23:28]
	return arp
}

func (arp *Arp) Print() {
	fmt.Printf("Htype=%#x\n", arp.Htype)
	fmt.Printf("Ptype=%#x\n", arp.Ptype)
	fmt.Printf("Hlen=%#x\n", arp.Hlen)
	fmt.Printf("Plen=%#x\n", arp.Plen)
	fmt.Printf("Op=%#x\n", arp.Op)
	fmt.Printf("SenderMac=%#x\n", arp.SenderMac)
	fmt.Printf("SenderIp=%#x\n", arp.SenderIP)
	fmt.Printf("TargetMac=%#x\n", arp.TargetMac)
	fmt.Printf("TargetIP=%#x\n", arp.TargetIP)
}

package pcap

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/atpons/39ac/pcaptool/pkg/util"
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

func (a *Arp) Marshal() []byte {
	b := make([]byte, 16)
	copy(b[0:2], a.Htype)
	copy(b[2:4], a.Ptype)
	copy(b[4:5], a.Hlen)
	copy(b[5:6], a.Plen)
	copy(b[6:8], a.Op)
	copy(b[8:14], a.SenderMac)
	copy(b[14:18], a.SenderIP)
	copy(b[18:23], a.TargetMac)
	copy(b[23:28], a.TargetIP)
	return b
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
	senderMac, err := util.LookupMacAddress(hex.EncodeToString(arp.SenderMac))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot Parse SenderMac: %s\n", hex.EncodeToString(arp.SenderMac))
	} else {
		fmt.Printf("SenderMac Company: %s\n", senderMac.Company())
	}
	fmt.Printf("SenderIp=%#x\n", arp.SenderIP)
	fmt.Printf("TargetMac=%#x\n", arp.TargetMac)
	targetMac, err := util.LookupMacAddress(hex.EncodeToString(arp.TargetMac))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot Parse TargetMac")
	} else {
		fmt.Printf("TargetMacCompany: %s\n", targetMac.Company())
	}
	fmt.Printf("TargetIP=%#x\n", arp.TargetIP)
}

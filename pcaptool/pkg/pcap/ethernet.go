package pcap

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/atpons/39ac/pcaptool/pkg/bpf"
)

type L2 interface {
	Print()
}

type Ethernet struct {
	Dst  []byte
	Src  []byte
	Type []byte
}

func (eth *Ethernet) Print() {
	// FIXME: got stuck with print :(
	//srcMac, err := util.LookupMacAddress(hex.EncodeToString(eth.Src))
	//if err != nil {
	//	log.Printf("look up macerr: %v", err)
	//}
	//dstMac, err := util.LookupMacAddress(hex.EncodeToString(eth.Dst))
	//if err != nil {
	//	log.Printf("lookup mac err: %v", err)
	//}
	//fmt.Printf("Dst=%#x (%s), Src=%#x (%s), Type=%#x\n", eth.Dst, dstMac.Company(), eth.Src, srcMac.Company(), eth.Type)
}

func (eth *Ethernet) Bytes() []byte {
	var b []byte
	b = append(b, eth.Dst...)
	b = append(b, eth.Src...)
	b = append(b, eth.Type...)
	return b
}

func ReadEthernetPacket(buf *bufio.Reader) (RecData, error) {
	filterReader := bpf.NewFilterReader(buf, *bpf.ArpVm())

	raw := Ethernet{}
	by := make([]byte, 14)
	_, _ = io.ReadFull(filterReader, by)
	out, err := filterReader.Filter()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[*] Corrupted BPF Filter\n")
	} else {
		fmt.Fprintf(os.Stderr, "[*] Filter by %d bytes\n", out)
	}
	// _, err := buf.Read(by)
	//if err != nil {
	//	panic(err)
	//}
	raw.Dst = by[0:6]
	raw.Src = by[6:12]
	raw.Type = by[12:14]
	fmt.Printf("Ethernet Type=%#x\n", raw.Type)
	return &raw, nil
}

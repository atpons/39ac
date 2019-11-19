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
	fmt.Printf("Dst=%#x, Src=%#x, Type=%#x\n", eth.Dst, eth.Src, eth.Type)
}

func ReadEthernetPacket(buf *bufio.Reader) (RecData, error) {
	filterReader := bpf.NewFilterReader(*buf, *bpf.ArpVm())

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
	return &raw, nil
}

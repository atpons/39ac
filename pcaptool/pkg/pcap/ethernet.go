package pcap

import (
	"bufio"
	"fmt"
	"io"
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
	raw := Ethernet{}
	by := make([]byte, 14)
	_, _ = io.ReadFull(buf, by)
	// _, err := buf.Read(by)
	//if err != nil {
	//	panic(err)
	//}
	raw.Dst = by[0:6]
	raw.Src = by[6:12]
	raw.Type = by[12:14]
	return &raw, nil
}

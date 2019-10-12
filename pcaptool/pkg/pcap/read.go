package pcap

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/atpons/39ac/pcaptool/pkg/util"
)

type Data struct {
	Hdr    Hdr
	RecHdr RecHdr
}

type Field interface {
	Print()
}

func (d *Data) Print() {
	d.Hdr.Print()
	d.RecHdr.Print()
}

type Hdr struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	ThisZone     int32
	SigFigs      uint32
	SnapLen      uint32
	Network      uint32
}

type RecHdr struct {
	TsSec   uint32
	TsUsec  uint32
	InclLen uint32
	OrigLen uint32
}

func (h *Hdr) Print() {
	fmt.Printf("MagicNumber = %#x\n", h.MagicNumber)
	fmt.Printf("VersionMajor = %#x\n", h.VersionMajor)
	fmt.Printf("VersionMinor = %#x\n", h.VersionMinor)
	fmt.Printf("ThisZone = %#x\n", h.ThisZone)
	fmt.Printf("SigFigs = %#x\n", h.SigFigs)
	fmt.Printf("SnapLen = %#x\n", h.SnapLen)
	fmt.Printf("Network = %#x\n", h.Network)
}

func (r *RecHdr) Print() {
	fmt.Printf("TsSec = %#x\n", r.TsSec)
	t := util.TimeFromUnix(r.TsSec)
	fmt.Printf("TsSec (Format) = %s\n", t.Sprint())
	fmt.Printf("TsUsec = %#x\n", r.TsUsec)
	fmt.Printf("InclLen = %#x\n", r.InclLen)
	fmt.Printf("OrigLen = %#x\n", r.OrigLen)
}

func Read(name string) Data {
	p := Data{}

	file, err := os.Open(name)
	defer file.Close()
	if err != nil {
		panic(err)
	}

	buf := bufio.NewReader(file)
	p.Hdr = readHead(buf)
	p.RecHdr = readRecHdr(buf)
	return p
}

func readHead(buf *bufio.Reader) Hdr {
	hdr := Hdr{}
	readHeaderField(buf, &hdr.MagicNumber)
	readHeaderField(buf, &hdr.VersionMajor)
	readHeaderField(buf, &hdr.VersionMinor)
	readHeaderField(buf, &hdr.ThisZone)
	readHeaderField(buf, &hdr.SigFigs)
	readHeaderField(buf, &hdr.SnapLen)
	readHeaderField(buf, &hdr.Network)
	return hdr
}

func readRecHdr(buf *bufio.Reader) RecHdr {
	recHdr := RecHdr{}
	readHeaderField(buf, &recHdr.TsSec)
	readHeaderField(buf, &recHdr.TsUsec)
	readHeaderField(buf, &recHdr.InclLen)
	readHeaderField(buf, &recHdr.OrigLen)
	return recHdr
}

func readHeaderField(buf *bufio.Reader, data interface{}) error {
	err := binary.Read(buf, binary.LittleEndian, data)
	if err != nil {
		return err
	}
	return nil
}

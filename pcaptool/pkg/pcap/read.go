package pcap

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/atpons/39ac/pcaptool/pkg/util"
)

type PacketList []Packet

func (p *PacketList) Print() {
	for index, v := range *p {
		fmt.Printf("Num: %d\n", index)
		v.RecHdr.Print()
		v.RecData.Print()
	}
}

type Data struct {
	Hdr  Hdr
	Data PacketList
}

type Field interface {
	Print()
}

type RecData interface {
	Print()
}

func (d *Data) Print() {
	d.Hdr.Print()
	d.Data.Print()
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

type Packet struct {
	RecHdr  RecHdr
	RecData RecData
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
	for {
		packet, err := readPacket(buf)
		if err != nil {
			break
		}
		p.Data = append(p.Data, *packet)
	}
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

func readRecHdr(buf *bufio.Reader) (*RecHdr, error) {
	recHdr := RecHdr{}
	if err := readHeaderField(buf, &recHdr.TsSec); err != nil {
		return nil, err
	}

	if err := readHeaderField(buf, &recHdr.TsUsec); err != nil {
		return nil, err
	}
	if err := readHeaderField(buf, &recHdr.InclLen); err != nil {
		return nil, err
	}
	if err := readHeaderField(buf, &recHdr.OrigLen); err != nil {
		return nil, err
	}
	return &recHdr, nil
}

func readHeaderField(buf *bufio.Reader, data interface{}) error {
	err := binary.Read(buf, binary.LittleEndian, data)
	if err != nil {
		return err
	}
	return nil
}

type RawData struct {
	Data []byte
}

func (r *RawData) Print() {
	fmt.Printf("RawData = %#x\n", r)
}

func readPacket(buf *bufio.Reader) (*Packet, error) {
	packet := Packet{}
	hdr, err := readRecHdr(buf)
	if err != nil {
		return nil, err
	}
	packet.RecHdr = *hdr
	data, err := readRawData(packet.RecHdr.InclLen, buf)
	if err != nil {
		return nil, err
	}
	packet.RecData = data
	return &packet, err
}

func readRawData(length uint32, buf *bufio.Reader) (RecData, error) {
	switch true {
	case true:
		raw := RawData{}
		by := make([]byte, length)
		_, err := buf.Read(by)
		if err != nil {
			return nil, err
		}
		raw.Data = by
		return &raw, nil
	default:
		panic("not implemented")
	}
}

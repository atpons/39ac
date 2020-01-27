package pcap

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"golang.org/x/net/ipv4"
)

type IP ipv4.Header

func (i IP) Print() {
	info := fmt.Sprintf("ver=%d i.rlen=%d tos=%#x totallen=%d id=%#x flags=%#x fragoff=%#x ttl=%d proto=%d cksum=%#x src=%v dst=%v", i.Version, i.Len, i.TOS, i.TotalLen, i.ID, i.Flags, i.FragOff, i.TTL, i.Protocol, i.Checksum, i.Src, i.Dst)
	fmt.Fprintln(os.Stdout, info)
}

func (i IP) Bytes() []byte {
	ip := ipv4.Header(i)
	b, _ := ip.Marshal()
	ip.Checksum = int(i.calcChecksum(b))
	b, _ = ip.Marshal()
	return b
}

// ref: http://tyamagu2.xyz/articles/go_ping/
// https://tools.ietf.org/html/rfc1071
func (i IP) calcChecksum(b []byte) uint16 {
	c := len(b)
	csum := uint32(0)
	for i := 0; i < c-1; i += 2 {
		csum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if c&1 != 0 {
		csum += uint32(b[c-1]) << 8
	}
	// of
	for (csum >> 16) > 0 {
		csum = (csum & 0xffff) + (csum >> 16)
	}
	return ^(uint16(csum))
}

func ReadIP(len int, buf *bufio.Reader) (IP, []byte) {
	fmt.Fprintf(os.Stderr, "Remain Data: %d\n", len)
	data := make([]byte, len)
	io.ReadFull(buf, data)
	ip := ipv4.Header{}
	err := ip.Parse(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%#v", err)
	}
	return IP(ip), data[ip.Len:]
}

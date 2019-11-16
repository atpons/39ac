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

func ReadIP(len int, buf *bufio.Reader) IP {
	fmt.Fprintf(os.Stderr, "Remain Data: %d\n", len)
	data := make([]byte, len)
	io.ReadFull(buf, data)
	ip := ipv4.Header{}
	err := ip.Parse(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%#v", err)
	}
	return IP(ip)
}

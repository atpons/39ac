package raw

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/atpons/39ac/pcaptool/pkg/pcap"
)

const (
	byteSize = 4096
)

type Socket struct {
	fd int
}

func NewSocket() (*Socket, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, err
	}
	return &Socket{fd: fd}, nil
}

func (s *Socket) Start(dev string) error {
	err := setPromisc(s.fd, dev)
	if err != nil {
		return err
	}

	file := getFile(s.fd)
	return ScanSocket(file)
}

func setPromisc(fd int, dev string) error {
	iface, err := net.InterfaceByName(dev)
	if err != nil {
		return err
	}

	if err := unix.SetsockoptPacketMreq(fd, syscall.SOL_PACKET, syscall.PACKET_ADD_MEMBERSHIP, &unix.PacketMreq{
		Ifindex: int32(iface.Index),
		Type:    syscall.PACKET_MR_PROMISC,
	}); err != nil {
		return err
	}

	return nil
}

func getFile(fd int) *os.File {
	return os.NewFile(uintptr(fd), "")
}

func ScanSocket(f *os.File) error {
	for {
		buf := make([]byte, byteSize)
		num, err := f.Read(buf)
		fmt.Println("Read ok")
		if err != nil {
			break
		} else {
			data := buf[:num]
			packet, err := pcap.ReadRawPacket(data)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			} else {
				for _, d := range packet.RecData {
					d.Print()
				}
			}
			fmt.Fprintf(os.Stderr, "Recv %d bytes\n", len(data))
		}
	}
	return nil
}

func (s *Socket) Close() error {
	return syscall.Close(s.fd)
}

func htons(host uint16) uint16 {
	return (host&0xff)<<8 | (host >> 8)
}

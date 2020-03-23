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
	dev       string
	bridgeDev string
	fd        int
	bridgeFd  int
}

func NewSocket(dev string, opts ...func(*Socket) error) (*Socket, error) {
	s := &Socket{dev: dev}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, err
	}

	s.fd = fd

	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}

	return s, nil
}

func OptionBridge(brdev string) func(*Socket) error {
	return func(s *Socket) error {
		fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
		if err != nil {
			return err
		}
		iface, err := net.InterfaceByName(brdev)
		if err != nil {
			return err
		}
		var haddr [8]byte
		copy(haddr[0:7], iface.HardwareAddr[0:7])
		addr := syscall.SockaddrLinklayer{
			Protocol: syscall.ETH_P_IP,
			Ifindex:  iface.Index,
			Halen:    uint8(len(iface.HardwareAddr)),
			Addr:     haddr,
		}
		s.bridgeFd = fd
		s.bridgeDev = brdev
		if err := syscall.Bind(fd, &addr); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "Complete bind\n")
		return nil
	}
}

func (s *Socket) Start() error {
	err := setPromisc(s.fd, s.dev)
	if err != nil {
		return err
	}

	file := getFile(s.fd)
	return s.ScanSocket(file)
}

func setPromisc(fd int, dev string) error {
	fmt.Fprintf(os.Stderr, "Getting Device dev=%s\n", dev)
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

func (s *Socket) ScanSocket(f *os.File) error {
	for {
		buf := make([]byte, byteSize)
		num, err := f.Read(buf)
		fmt.Println("Read ok")
		if err != nil {
			break
		} else {
			data := buf[:num]
			if s.bridgeFd != 0 {
				if _, err := syscall.Write(s.bridgeFd, data); err != nil {
					fmt.Fprintf(os.Stderr, "[-] Bridge Error: %v\n", err)
				}
			}
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
		break
	}
	return nil
}

func (s *Socket) Close() error {
	return syscall.Close(s.fd)
}

func htons(host uint16) uint16 {
	return (host&0xff)<<8 | (host >> 8)
}

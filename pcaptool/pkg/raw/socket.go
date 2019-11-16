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

func Start() error {
	// thanks to https://github.com/yudaishimanaka/rawdump code.

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	nic, _ := net.InterfaceByName(os.Args[1])
	//addr := syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: nic.Index}
	//
	//if err := syscall.Bind(fd, &addr); err != nil {
	//	return err
	//}

	if err := unix.SetsockoptPacketMreq(fd, syscall.SOL_PACKET, syscall.PACKET_ADD_MEMBERSHIP, &unix.PacketMreq{
		Ifindex: int32(nic.Index),
		Type:    syscall.PACKET_MR_PROMISC,
	}); err != nil {
		return err
	}

	f := os.NewFile(uintptr(fd), "")

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

func htons(host uint16) uint16 {
	return (host&0xff)<<8 | (host >> 8)
}

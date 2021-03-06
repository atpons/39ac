package raw

import (
	"fmt"
	"log"
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
	Dev       string
	BridgeDev string
	NextHop   [8]byte

	Fd       int
	BridgeFd int
}

func NewSocket(dev string, opts ...func(*Socket) error) (*Socket, error) {
	s := &Socket{Dev: dev}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, err
	}

	s.Fd = fd

	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}

	return s, nil
}

func OptionNextHop(nextHop [8]byte) func(*Socket) error {
	return func(s *Socket) error {
		s.NextHop = nextHop
		return nil
	}
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
		s.BridgeFd = fd
		s.BridgeDev = brdev
		if err := syscall.Bind(fd, &addr); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "Complete bind\n")
		return nil
	}
}

func (s *Socket) Start(fd int, dev string, scanFunc func(f *os.File) error) error {
	err := setPromisc(fd, dev)
	if err != nil {
		return err
	}

	file := getFile(fd)
	return scanFunc(file)
}

func setPromisc(fd int, dev string) error {
	fmt.Fprintf(os.Stderr, "Getting Device Dev=%s\n", dev)
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

func (s *Socket) ScanSniff(f *os.File) error {
	for {
	Loop:
		buf := make([]byte, byteSize)
		num, err := f.Read(buf)
		if err != nil {
			break
		} else {
			data := buf[:num]
			_, err := pcap.ReadRawPacket(data)
			if err != nil {
				log.Println(err)
				goto Loop
			}
		}
	}
	return nil
}

func (s *Socket) ScanSocket(f *os.File) error {
	for {
		buf := make([]byte, byteSize)
		num, err := f.Read(buf)
		fmt.Println("Read ok")
		if err != nil {
			break
		} else {
			//var addr syscall.SockaddrLinklayer
			data := buf[:num]
			if s.BridgeFd != 0 {
				if _, err := syscall.Write(s.BridgeFd, data); err != nil {
					fmt.Fprintf(os.Stderr, "[-] Bridge Error: %v\n", err)
				}
			}
			_, err := pcap.ReadRawPacket(data)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			} else {
				//	var newData []byte
				//	var dstMac []byte
				//	for _, d := range packet.RecData {
				//		d.Print()
				//		if s.BridgeFd != 0 {
				//			if v, ok := d.(*pcap.IP); ok {
				//				dstMac, err = store.Global.GetARP(v.Dst.To4())
				//				if err != nil {
				//					log.Printf("dstMac not dound: err=%v reqDst=%v", err, v.Dst.To4())
				//					goto Loop
				//				}
				//				v.TTL -= 1
				//
				//			}
				//		}
				//	}
				//	for _, d := range packet.RecData {
				//		if s.BridgeFd != 0 {
				//			if v, ok := d.(*pcap.Ethernet); ok {
				//				if len(dstMac) < 6 {
				//					log.Printf("dstMac error dstMac=%v", dstMac)
				//					goto Loop
				//				}
				//				iface, _ := net.InterfaceByName(s.Dev)
				//				//if !bytes.Equal(iface.HardwareAddr, v.Dst) {
				//				//	log.Printf("[-] Not Match MAC: HWAddr: %#v, DstMac: %#v", iface.HardwareAddr, v.Dst)
				//				//	goto Loop
				//				//}
				//				copy(v.Dst[0:6], dstMac[0:6])
				//				var dstMacByte [8]byte
				//				copy(dstMacByte[0:6], dstMac[0:6])
				//				if reflect.DeepEqual(v.Src[0:6], v.Dst[0:6]) {
				//					log.Printf("reject by match dst and src")
				//					continue
				//					//goto Loop
				//				} else {
				//					log.Printf("routing packet to %v", v)
				//				}
				//				copy(v.Src[0:6], iface.HardwareAddr[0:6])
				//				log.Printf("routing packet to %x -> %x, %v", v.Src, v.Dst, v)
				//				addr = syscall.SockaddrLinklayer{
				//					Protocol: syscall.ETH_P_IP,
				//					Halen:    6,
				//					Ifindex:  iface.Index,
				//					Addr:     dstMacByte,
				//				}
				//			}
				//		}
				//		newData = append(newData, d.Bytes()...)
				//	}
				//	log.Printf("Sendto from %s to %X", s.Dev, addr.Addr)
				//	if err := syscall.Sendto(s.Fd, newData, 0, &addr); err != nil {
				//		log.Println(err)
				//	} else {
				//		log.Printf("[*] Send OK")
				//	}
			}
			fmt.Fprintf(os.Stderr, "Recv %d bytes\n", len(data))
		}
	}
	return nil
}

func (s *Socket) Close() error {
	return syscall.Close(s.Fd)
}

func htons(host uint16) uint16 {
	return (host&0xff)<<8 | (host >> 8)
}

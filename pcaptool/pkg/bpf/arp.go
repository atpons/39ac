package bpf

import (
	"bufio"
	"sync"

	"golang.org/x/net/bpf"
)

const (
	etOff = 12
	etLen = 2

	etARP = 0x0806
)

type Reader interface {
	Read([]byte) (int, error)
}

type FilterReader struct {
	mu     sync.Mutex
	buf    []byte
	vm     *bpf.VM
	reader *bufio.Reader
}

func NewFilterReader(reader *bufio.Reader, vm bpf.VM) *FilterReader {
	return &FilterReader{reader: reader, vm: &vm}
}

func (f *FilterReader) Read(p []byte) (int, error) {
	n, err := f.reader.Read(p)
	f.mu.Lock()
	f.buf = make([]byte, len(p))
	copy(f.buf, p)
	f.mu.Unlock()
	return n, err
}

func (f *FilterReader) Filter() (int, error) {
	out, err := f.vm.Run(f.buf)
	if err != nil {
		return out, err
	}
	if out > len(f.buf) {
		out = len(f.buf)
	}
	return out, err
}

func ArpVm() *bpf.VM {
	vm, _ := bpf.NewVM([]bpf.Instruction{
		// Load EtherType value from Ethernet header
		bpf.LoadAbsolute{
			Off:  etOff,
			Size: etLen,
		},
		// If EtherType is equal to the ARP EtherType, jump to allow
		// packet to be accepted
		bpf.JumpIf{
			Cond:     bpf.JumpEqual,
			Val:      etARP,
			SkipTrue: 1,
		},
		// EtherType does not match the ARP EtherType
		bpf.RetConstant{
			Val: 0,
		},
		// EtherType matches the ARP EtherType, accept up to 1500
		// bytes of packet
		bpf.RetConstant{
			Val: 1500,
		},
	})
	return vm
}

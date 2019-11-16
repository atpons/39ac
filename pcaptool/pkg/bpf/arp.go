package bpf

import (
	"fmt"

	"golang.org/x/net/bpf"
)

const (
	etOff = 12
	etLen = 2

	etARP = 0x0806
)

func Filter(frame []byte) (int, error) {
	vm, err := bpf.NewVM([]bpf.Instruction{
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
	if err != nil {
		return 0, fmt.Errorf("failed to load BPF program: %v", err)
	}

	// Run our VM's BPF program using the Ethernet frame as input
	out, err := vm.Run(frame)
	if err != nil {
		return 0, fmt.Errorf("failed to accept Ethernet frame: %v", err)
	}

	// BPF VM can return a byte count greater than the number of input
	// bytes, so trim the output to match the input byte length
	if out > len(frame) {
		out = len(frame)
	}

	return out, nil
}

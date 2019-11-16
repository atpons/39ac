package main

import (
	"fmt"

	"golang.org/x/net/bpf"
)

// Offset | Length | Comment
// -------------------------
//   00   |   06   | Ethernet destination MAC address
//   06   |   06   | Ethernet source MAC address
//   12   |   02   | Ethernet EtherType
const (
	etOff = 12
	etLen = 2

	etARP = 0x0806
)

func main() {
	// Set up a VM to filter traffic based on if its EtherType
	// matches the ARP EtherType.
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
		panic(fmt.Sprintf("failed to load BPF program: %v", err))
	}

	// Create an Ethernet frame with the ARP EtherType for testing
	frame := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x08, 0x06,
		// Payload omitted for brevity
	}

	// Run our VM's BPF program using the Ethernet frame as input
	out, err := vm.Run(frame)
	if err != nil {
		panic(fmt.Sprintf("failed to accept Ethernet frame: %v", err))
	}

	// BPF VM can return a byte count greater than the number of input
	// bytes, so trim the output to match the input byte length
	if out > len(frame) {
		out = len(frame)
	}

	fmt.Printf("out: %d bytes", out)
}

package main

import (
	"fmt"
	"os"

	"github.com/atpons/39ac/pcaptool/pkg/raw"
)

func main() {
	err := raw.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}
}

package main

import (
	_ "embed"
	"fmt"
	"github.com/praetorian-inc/goffloader/src/coff"
	"github.com/praetorian-inc/goffloader/src/lighthouse"
)

//go:embed whoami.x64.o
var whoamiBofBytes []byte

func main() {
	// Note that args need to be prefaced with their type string as expected in aggressor scripts
	// see an example of this in pe_windows.go for a more complex arg set
	argBytes, err := lighthouse.PackArgs([]string{"zArgs", "zYou", "zWant"})
	if err != nil {
		panic(err)
	}
	output, err := coff.Load(whoamiBofBytes, argBytes)
	if err != nil {
		panic(err)
	}
	fmt.Println(output)
}

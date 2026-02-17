package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

var (
	entry  uint
	loader bool
)

func init() {
	flag.UintVar(&entry, "e", 0, "test no hook mode")
	flag.BoolVar(&loader, "l", false, "is an entry to loader")
	flag.Parse()
}

func main() {
	if entry != 0 {
		testNoHookMode()
	}

	// just make pe image larger for
	// create more code caves in .text
	http.NewServeMux()

	for {
		fmt.Println("Hello World!")
		time.Sleep(time.Second)
	}
}

func testNoHookMode() {
	peb := windows.RtlGetCurrentPeb()
	addr := peb.ImageBaseAddress + uintptr(entry)

	if !loader {
		rd := rand.New(rand.NewSource(time.Now().UnixNano()))
		num1 := rd.Uint32()
		num2 := rd.Uint32()
		// test function entry is a simple Add
		ret, _, _ := syscall.SyscallN(addr, uintptr(num1), uintptr(num2))
		if uint32(ret) != num1+num2 {
			panic("invalid entry address")
		}
		return
	}
}

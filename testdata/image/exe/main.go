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
	fmt.Printf("entry: 0x%X", addr)

	if loader {
		ret, _, _ := syscall.SyscallN(addr)
		if ret == 0 || ret == 1 || ret == addr {
			return
		}
		// maybe thread handle
		if ret < 0xFFFF {
			return
		}
		panic(fmt.Sprintf("invalid return value: 0x%X", ret))
	}

	// test function entry is a simple Add
	rd := rand.New(rand.NewSource(time.Now().UnixNano()))
	num1 := rd.Uint32()
	num2 := rd.Uint32()
	ret, _, _ := syscall.SyscallN(addr, uintptr(num1), uintptr(num2))
	if uint32(ret) == num1+num2 {
		return
	}
	panic("invalid add result")
}

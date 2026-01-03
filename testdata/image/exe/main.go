package main

import (
	"fmt"
	"net/http"
	"time"
)

func main() {
	http.NewServeMux()
	for {
		fmt.Println("Hello World!")
		time.Sleep(time.Second)
	}
}

package main

import (
	"io"
	"log"
	"net"
)

func main() {
	lsn, err := net.Listen("tcp", "0.0.0.0:10010")
	if err != nil {
		log.Fatalf("Listen failed: %s", err)
	}
	for {
		conn, err := lsn.Accept()
		if err != nil {
			log.Fatalf("Accept failed: %s", err)
		}
		log.Printf("New client: %s", conn.RemoteAddr())

		go func() {
			defer conn.Close()
			io.Copy(conn, conn)
			log.Print("Closed")
		}()
	}
}

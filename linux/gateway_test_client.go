package main

import (
	"bytes"
	"io"
	"log"
	"math/rand"
	"net"
	"time"
)

func main() {
	conn, err := net.Dial("tcp", "127.0.0.1:10080")
	if err != nil {
		log.Fatal(err)
	}

	conn.Write([]byte("U2FsdGVkX1+JXKDI/2wFpglXX2zzASqnKhqAiM6GvoI=\n"))
	code := make([]byte, 3)
	_, err = io.ReadFull(conn, code)
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(code, []byte("200")) {
		log.Fatal()
	}

	t1 := time.Now()
	for i := 0; i < 100000; i++ {
		//println(i)
		b1 := RandBytes(256)
		b2 := make([]byte, len(b1))

		_, err := conn.Write(b1)
		if err != nil {
			log.Fatal(err)
		}

		_, err = io.ReadFull(conn, b2)
		if err != nil {
			log.Fatal(err)
		}

		if !bytes.Equal(b1, b2) {
			log.Fatal()
		}
	}
	log.Println("Finish:", time.Since(t1).String())
}

func RandBytes(n int) []byte {
	n = rand.Intn(n) + 1
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = byte(rand.Intn(255))
	}
	return b
}

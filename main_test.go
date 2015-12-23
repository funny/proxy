package main

import (
	"bufio"
	"io"
	"math/rand"
	"net"
	"testing"

	"github.com/funny/gateway/aes256cbc"
	"github.com/funny/utest"
)

func RandBytes(n int) []byte {
	n = rand.Intn(n) + 1
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = byte(rand.Intn(255))
	}
	return b
}

func Test_Normal(t *testing.T) {
	cfgSecret = []byte("test")

	addr := gateway()

	clientAddrChan := make(chan string, 1)

	listener, err := net.Listen("tcp", "0.0.0.0:0")
	utest.IsNilNow(t, err)
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			utest.IsNilNow(t, err)

			go func() {
				defer conn.Close()

				reader := bufio.NewReader(conn)
				n, err := reader.ReadByte()
				utest.IsNilNow(t, err)

				clientAddr := make([]byte, n)
				_, err = io.ReadFull(reader, clientAddr)
				utest.IsNilNow(t, err)
				utest.EqualNow(t, <-clientAddrChan, string(clientAddr))

				io.Copy(conn, conn)
			}()
		}
	}()

	conn, err := net.Dial("tcp", addr)
	utest.IsNilNow(t, err)
	defer conn.Close()
	clientAddrChan <- conn.LocalAddr().String()

	encryptedAddr, err := aes256cbc.EncryptString("test", listener.Addr().String())
	utest.IsNilNow(t, err)

	_, err = conn.Write([]byte(encryptedAddr))
	utest.IsNilNow(t, err)
	_, err = conn.Write([]byte("\n"))
	utest.IsNilNow(t, err)

	code := make([]byte, 3)
	_, err = io.ReadFull(conn, code)
	utest.IsNilNow(t, err)
	utest.EqualNow(t, string(code), string(codeOK))

	for j := 0; j < 10000; j++ {
		b1 := RandBytes(256)
		_, err = conn.Write(b1)
		utest.IsNilNow(t, err)

		b2 := make([]byte, len(b1))
		_, err = io.ReadFull(conn, b2)
		utest.IsNilNow(t, err)

		utest.EqualNow(t, b1, b2)
	}
}

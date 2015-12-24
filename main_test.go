package main

import (
	"bufio"
	"io"
	"math/rand"
	"net"
	"os"
	gotest "testing"
	"time"

	"github.com/funny/gateway/aes256cbc"
	"github.com/funny/utest"
)

func init() {
	os.Setenv("GW_SECRET", "test")
	os.Setenv("GW_PORT", "0")
	os.Setenv("GW_DIAL_TIMEOUT", "1")
	os.Setenv("GW_DIAL_RETRY", "1")
	os.Setenv("GW_PPROF_ADDR", "0.0.0.0:0")

	testing = true
	main()
}

func RandBytes(n int) []byte {
	n = rand.Intn(n) + 1
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = byte(rand.Intn(255))
	}
	return b
}

func Test_BadReq(t *gotest.T) {
	conn, err := net.Dial("tcp", gatewayAddr)
	utest.IsNilNow(t, err)
	defer conn.Close()

	err = conn.(*net.TCPConn).CloseWrite()
	utest.IsNilNow(t, err)

	code := make([]byte, 3)
	_, err = io.ReadFull(conn, code)
	utest.IsNilNow(t, err)
	utest.EqualNow(t, string(code), string(codeBadReq))
}

func Test_TextBadReq(t *gotest.T) {
	conn, err := net.Dial("tcp", gatewayAddr)
	utest.IsNilNow(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("abc"))
	utest.IsNilNow(t, err)

	err = conn.(*net.TCPConn).CloseWrite()
	utest.IsNilNow(t, err)

	code := make([]byte, 3)
	_, err = io.ReadFull(conn, code)
	utest.IsNilNow(t, err)
	utest.EqualNow(t, string(code), string(codeBadReq))
}

func Test_BinaryBadReq1(t *gotest.T) {
	conn, err := net.Dial("tcp", gatewayAddr)
	utest.IsNilNow(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte{0})
	utest.IsNilNow(t, err)

	err = conn.(*net.TCPConn).CloseWrite()
	utest.IsNilNow(t, err)

	code := make([]byte, 3)
	_, err = io.ReadFull(conn, code)
	utest.IsNilNow(t, err)
	utest.EqualNow(t, string(code), string(codeBadReq))
}

func Test_BinaryBadReq2(t *gotest.T) {
	conn, err := net.Dial("tcp", gatewayAddr)
	utest.IsNilNow(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte{0, 3})
	utest.IsNilNow(t, err)

	err = conn.(*net.TCPConn).CloseWrite()
	utest.IsNilNow(t, err)

	code := make([]byte, 3)
	_, err = io.ReadFull(conn, code)
	utest.IsNilNow(t, err)
	utest.EqualNow(t, string(code), string(codeBadReq))
}

func Test_TextBadAddr(t *gotest.T) {
	conn, err := net.Dial("tcp", gatewayAddr)
	utest.IsNilNow(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("abc\n"))
	utest.IsNilNow(t, err)

	code := make([]byte, 3)
	_, err = io.ReadFull(conn, code)
	utest.IsNilNow(t, err)
	utest.EqualNow(t, string(code), string(codeBadAddr))
}

func Test_BinaryBadAddr(t *gotest.T) {
	conn, err := net.Dial("tcp", gatewayAddr)
	utest.IsNilNow(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte{0, 1, 2})
	utest.IsNilNow(t, err)

	code := make([]byte, 3)
	_, err = io.ReadFull(conn, code)
	utest.IsNilNow(t, err)
	utest.EqualNow(t, string(code), string(codeBadAddr))
}

func Test_CodeDialErr(t *gotest.T) {
	conn, err := net.Dial("tcp", gatewayAddr)
	utest.IsNilNow(t, err)
	defer conn.Close()

	encryptedAddr, err := aes256cbc.EncryptString("test", "0.0.0.0:0")
	utest.IsNilNow(t, err)

	_, err = conn.Write([]byte(encryptedAddr))
	utest.IsNilNow(t, err)
	_, err = conn.Write([]byte("\n"))
	utest.IsNilNow(t, err)

	code := make([]byte, 3)
	_, err = io.ReadFull(conn, code)
	utest.IsNilNow(t, err)
	utest.EqualNow(t, string(code), string(codeDialErr))
}

func Test_CodeDialTimeout(t *gotest.T) {
	oldTimeout := cfgDialTimeout
	cfgDialTimeout = 10 * time.Microsecond
	defer func() {
		cfgDialTimeout = oldTimeout
	}()

	listener, err := net.Listen("tcp", "0.0.0.0:0")
	utest.IsNilNow(t, err)
	defer listener.Close()

	conn, err := net.Dial("tcp", gatewayAddr)
	utest.IsNilNow(t, err)
	defer conn.Close()

	encryptedAddr, err := aes256cbc.EncryptString("test", listener.Addr().String())
	utest.IsNilNow(t, err)

	_, err = conn.Write([]byte(encryptedAddr))
	utest.IsNilNow(t, err)
	_, err = conn.Write([]byte("\n"))
	utest.IsNilNow(t, err)

	code := make([]byte, 3)
	_, err = io.ReadFull(conn, code)
	utest.IsNilNow(t, err)
	utest.EqualNow(t, string(code), string(codeDialTimeout))
}

func Test_BinaryOK(t *gotest.T) {
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	utest.IsNilNow(t, err)
	defer listener.Close()

	conn, err := net.Dial("tcp", gatewayAddr)
	utest.IsNilNow(t, err)
	defer conn.Close()

	encryptedAddr, err := aes256cbc.Encrypt(cfgSecret, []byte(listener.Addr().String()))
	utest.IsNilNow(t, err)

	_, err = conn.Write([]byte{0x0})
	utest.IsNilNow(t, err)
	_, err = conn.Write([]byte{byte(len(encryptedAddr))})
	utest.IsNilNow(t, err)
	_, err = conn.Write([]byte(encryptedAddr))
	utest.IsNilNow(t, err)

	code := make([]byte, 3)
	_, err = io.ReadFull(conn, code)
	utest.IsNilNow(t, err)
	utest.EqualNow(t, string(code), string(codeOK))
}

func Test_TextOK(t *gotest.T) {
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	utest.IsNilNow(t, err)
	defer listener.Close()

	conn, err := net.Dial("tcp", gatewayAddr)
	utest.IsNilNow(t, err)
	defer conn.Close()

	encryptedAddr, err := aes256cbc.EncryptString(string(cfgSecret), listener.Addr().String())
	utest.IsNilNow(t, err)

	_, err = conn.Write([]byte(encryptedAddr))
	utest.IsNilNow(t, err)
	_, err = conn.Write([]byte("\n"))
	utest.IsNilNow(t, err)

	code := make([]byte, 3)
	_, err = io.ReadFull(conn, code)
	utest.IsNilNow(t, err)
	utest.EqualNow(t, string(code), string(codeOK))
}

func Test_Normal(t *gotest.T) {
	clientAddrChan := make(chan string, 1)

	listener, err := net.Listen("tcp", "0.0.0.0:0")
	utest.IsNilNow(t, err)
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}

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

	conn, err := net.Dial("tcp", gatewayAddr)
	utest.IsNilNow(t, err)
	defer conn.Close()
	clientAddrChan <- conn.LocalAddr().String()

	encryptedAddr, err := aes256cbc.EncryptString(string(cfgSecret), listener.Addr().String())
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

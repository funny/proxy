package main

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/funny/crypto/aes256cbc"
	"github.com/funny/utest"
)

func Test_BadReq(t *testing.T) {
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

func Test_TextBadReq(t *testing.T) {
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

func Test_BinaryBadReq1(t *testing.T) {
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

func Test_BinaryBadReq2(t *testing.T) {
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

func Test_TextBadAddr(t *testing.T) {
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

func Test_BinaryBadAddr(t *testing.T) {
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

func Test_CodeDialErr(t *testing.T) {
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

func Test_CodeDialTimeout(t *testing.T) {
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

func Test_BinaryOK(t *testing.T) {
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

func Test_TextOK(t *testing.T) {
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

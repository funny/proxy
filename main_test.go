package main

import (
	"io"
	"math/rand"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/funny/crypto/aes256cbc"
	"github.com/funny/utest"
)

func init() {
	isTest = true
	os.Setenv("GW_SECRET", "test")
	os.Setenv("GW_ADDR", "")
	os.Setenv("GW_DIAL_TIMEOUT", "1")
	os.Setenv("GW_DIAL_RETRY", "1")
	os.Setenv("GW_PPROF_ADDR", "0.0.0.0:0")
	os.Setenv("GW_BUFF_SIZE", "32000")
	go main()
	time.Sleep(time.Second * 2)
}

func RandBytes(n int) []byte {
	n = rand.Intn(n) + 1
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = byte(rand.Intn(255))
	}
	return b
}

func Test_Config(t *testing.T) {
	os.Setenv("GW_DIAL_TIMEOUT", "")
	os.Setenv("GW_DIAL_RETRY", "")
	os.Setenv("GW_PPROF_ADDR", "")

	os.Setenv("GW_SECRET", "")
	func() {
		defer func() {
			err := recover()
			utest.NotNilNow(t, err)
			utest.Assert(t, strings.Contains(err.(string), "GW_SECRET"))
		}()
		config()
	}()
	os.Setenv("GW_SECRET", "test")

	os.Setenv("GW_DIAL_RETRY", "a")
	func() {
		defer func() {
			err := recover()
			utest.NotNilNow(t, err)
			utest.Assert(t, strings.Contains(err.(string), "GW_DIAL_RETRY"))
		}()
		config()
	}()
	os.Setenv("GW_DIAL_RETRY", "0")

	os.Setenv("GW_DIAL_TIMEOUT", "a")
	func() {
		defer func() {
			err := recover()
			utest.NotNilNow(t, err)
			utest.Assert(t, strings.Contains(err.(string), "GW_DIAL_TIMEOUT"))
		}()
		config()
	}()
	os.Setenv("GW_DIAL_TIMEOUT", "0")

	os.Setenv("GW_PPROF_ADDR", "abc")
	func() {
		defer func() {
			err := recover()
			utest.NotNilNow(t, err)
			utest.Assert(t, strings.Contains(err.(string), "pprof"))
		}()
		config()
	}()
	os.Setenv("GW_PPROF_ADDR", "")

	os.Setenv("GW_BUFF_SIZE", "abc")
	func() {
		defer func() {
			err := recover()
			utest.NotNilNow(t, err)
			utest.Assert(t, strings.Contains(err.(string), "GW_BUFF_SIZE"))
		}()
		config()
	}()
	os.Setenv("GW_BUFF_SIZE", "0")
	cfgBufferSize = 32 * 1024

	utest.EqualNow(t, cfgDialRetry, 1)
	utest.EqualNow(t, int(cfgDialTimeout), int(3*time.Second))
	cfgDialTimeout = time.Second
}

func Test_Start(t *testing.T) {
	cfgReusePort = true
	cfgAddr = "abc"
	func() {
		defer func() {
			err := recover()
			utest.NotNilNow(t, err)
			utest.Assert(t, strings.Contains(err.(string), "listener"))
		}()
		start()
	}()
}

func Test_BadReq1(t *testing.T) {
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

func Test_BadReq2(t *testing.T) {
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

func Test_BadAddr(t *testing.T) {
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

func Test_DialTimeout(t *testing.T) {
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

func Test_OK(t *testing.T) {
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

type TestError struct {
	timeout   bool
	temporary bool
}

func (e TestError) Error() string {
	return "This is test error"
}

func (e TestError) Timeout() bool {
	return e.timeout
}

func (e TestError) Temporary() bool {
	return e.temporary
}

type TestListener struct {
	n   int
	err TestError
}

func (l *TestListener) Accept() (net.Conn, error) {
	if l.n == -1 {
		return nil, l.err
	}
	if l.n == 0 {
		return &net.TCPConn{}, nil
	}
	l.n--
	return nil, l.err
}

func (l *TestListener) Close() error {
	return nil
}

func (l *TestListener) Addr() net.Addr {
	return nil
}

func Test_Accept(t *testing.T) {
	_, err := accept(&TestListener{
		9, TestError{false, true},
	})
	utest.IsNilNow(t, err)

	_, err = accept(&TestListener{
		-1, TestError{true, false},
	})
	utest.NotNilNow(t, err)

	func() {
		defer func() {
			err := recover()
			utest.NotNilNow(t, err)
			utest.Assert(t, strings.Contains(err.(string), "Gateway accept failed"))
		}()
		loop(&TestListener{
			-1, TestError{true, false},
		})
	}()
}

type TestReadWriteCloser struct {
	closed bool
}

func (t *TestReadWriteCloser) Write(_ []byte) (int, error) {
	panic("just panic")
}

func (t *TestReadWriteCloser) Read(_ []byte) (int, error) {
	panic("just panic")
}

func (t *TestReadWriteCloser) Close() error {
	t.closed = true
	return nil
}

func Test_Transfer(t *testing.T) {
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
				io.Copy(conn, conn)
			}()
		}
	}()

	for i := 0; i < 20; i++ {
		conn, err := net.Dial("tcp", gatewayAddr)
		utest.IsNilNow(t, err)
		defer conn.Close()

		encryptedAddr, err := aes256cbc.EncryptString(string(cfgSecret), listener.Addr().String())
		utest.IsNilNow(t, err)

		_, err = conn.Write([]byte(encryptedAddr))
		utest.IsNilNow(t, err)
		_, err = conn.Write([]byte("\nabc"))
		utest.IsNilNow(t, err)

		code := make([]byte, 6)
		_, err = io.ReadFull(conn, code)
		utest.IsNilNow(t, err)
		utest.EqualNow(t, string(code[:3]), string(codeOK))
		utest.EqualNow(t, string(code[3:]), "abc")

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
}

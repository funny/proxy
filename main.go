package main

import (
	"bufio"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/funny/gateway/aes256cbc"
	"github.com/funny/gateway/reuseport"
)

var (
	secret      []byte
	dialRetry   int
	dialTimeout time.Duration
)

var (
	errBadRequest  = errors.New("Bad request")
	errDialTimeout = errors.New("Dial timeout")
)

var (
	codeOK      = []byte("200")
	codeIO      = []byte("400")
	codeBad     = []byte("401")
	codeDial    = []byte("502")
	codePeekBuf = []byte("503")
	codeSendBuf = []byte("504")
)

var (
	bufioPool sync.Pool
	pool256   sync.Pool
)

func init() {
	pool256.New = func() interface{} {
		return make([]byte, 0, 256)
	}
}

func make256(n byte) []byte {
	return pool256.Get().([]byte)[:n]
}

func free256(b []byte) {
	pool256.Put(b)
}

func main() {
	if _, err := os.Stat("gateway.pid"); err == nil {
		log.Fatal("Already a pid file there")
	}
	pid := syscall.Getpid()
	if err := ioutil.WriteFile("gateway.pid", []byte(strconv.Itoa(pid)), 0644); err != nil {
		log.Fatal("Can't write pid file: %s", err)
	}
	defer os.Remove("gateway.pid")

	config()
	pprof()
	gateway()

	sigTERM := make(chan os.Signal, 1)
	sigINT := make(chan os.Signal, 1)

	signal.Notify(sigTERM, syscall.SIGTERM)
	signal.Notify(sigINT, syscall.SIGINT)

	log.Printf("Gateway running, pid = %d", pid)
	select {
	case <-sigINT:
	case <-sigTERM:
	}
	log.Printf("Gateway killed")
}

func config() {
	var err error

	secret = []byte(os.Getenv("GW_SECRET"))

	if v := os.Getenv("GW_DIAL_RETRY"); v != "" {
		dialRetry, err = strconv.Atoi(v)
		if err != nil {
			log.Fatalf("GW_DIAL_RETRY - %s", err)
		}
		if dialRetry == 0 {
			dialRetry = 1
		}
	}

	var timeout int
	if v := os.Getenv("GW_DIAL_TIMEOUT"); v != "" {
		timeout, err = strconv.Atoi(v)
		if err != nil {
			log.Fatalf("GW_DIAL_TIMEOUT - %s", err)
		}
		if timeout == 0 {
			timeout = 1
		}
	}
	dialTimeout = time.Duration(timeout) * time.Second
}

func pprof() {
	if v := os.Getenv("GW_PPROF_ADDR"); v != "" {
		listener, err := net.Listen("tcp", v)
		if err != nil {
			log.Fatalf("Setup pprof failed: %s", err)
		}
		log.Println("Setup pprof at %s", listener.Addr())
		go http.Serve(listener, nil)
	}
}

func gateway() {
	port := os.Getenv("GW_PORT")
	if port == "" {
		port = "0"
	}
	addr := "0.0.0.0:" + port
	reuse := os.Getenv("GW_REUSE_PORT") == "1"

	var err error
	var listener net.Listener

	if reuse {
		listener, err = reuseport.NewReusablePortListener("tcp4", addr)
	} else {
		listener, err = net.Listen("tcp", addr)
	}

	if err != nil {
		log.Fatalf("Setup listener failed: %s", err)
	}

	log.Printf("Setup gateway at %s", listener.Addr())
	go loop(listener)
}

func loop(listener net.Listener) {
	defer listener.Close()
	for {
		conn, err := accept(listener)
		if err != nil {
			log.Printf("Gateway accept failed: %s", err)
			return
		}
		go handle(conn)
	}
}

func accept(listener net.Listener) (net.Conn, error) {
	var tempDelay time.Duration
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				time.Sleep(tempDelay)
				continue
			}
			return nil, err
		}
		tempDelay = 0
		return conn, nil
	}
}

func handle(conn net.Conn) {
	defer func() {
		conn.Close()
		if err := recover(); err != nil {
			log.Printf("Unhandled panic in connection handler: %v\n\n%s", err, debug.Stack())
		}
	}()

	reader, ok := bufioPool.Get().(*bufio.Reader)
	if ok {
		reader.Reset(conn)
	} else {
		reader = bufio.NewReader(conn)
	}
	bufioReleased := false
	defer func() {
		if !bufioReleased {
			reader.Reset(nil)
			bufioPool.Put(reader)
		}
	}()

	addr, err := handshake(conn, reader)
	if err != nil {
		return
	}

	agent, err := dial(string(addr), conn.RemoteAddr().String())
	if err != nil {
		conn.Write(codeDial)
		return
	}

	buf, err := reader.Peek(reader.Buffered())
	if err != nil {
		conn.Write(codePeekBuf)
		return
	}
	if _, err := agent.Write(buf); err != nil {
		conn.Write(codeSendBuf)
		return
	}
	reader.Reset(nil)
	bufioPool.Put(reader)
	bufioReleased = true

	if _, err := conn.Write(codeOK); err != nil {
		return
	}
	go safeCopy(agent, conn)
	io.Copy(conn, agent)
}

func handshake(conn net.Conn, reader *bufio.Reader) ([]byte, error) {
	firstByte, err := reader.ReadByte()
	if err != nil {
		conn.Write(codeIO)
		return nil, err
	}
	switch firstByte {
	case 0:
		return handshakeBinary(conn, reader)
	default:
		if err = reader.UnreadByte(); err != nil {
			return nil, err
		}
		return handshakeText(conn, reader)
	}
}

func handshakeBinary(conn net.Conn, reader *bufio.Reader) (addr []byte, err error) {
	var n byte
	n, err = reader.ReadByte()
	if err != nil {
		conn.Write(codeIO)
		return nil, err
	}

	bin := make256(n)
	defer free256(bin)

	if _, err = io.ReadFull(reader, bin); err != nil {
		conn.Write(codeIO)
		return nil, err
	}
	if addr, err = aes256cbc.Decrypt(secret, bin); err != nil {
		conn.Write(codeBad)
		return nil, err
	}
	return
}

func handshakeText(conn net.Conn, reader *bufio.Reader) (addr []byte, err error) {
	base64, isPrefix, err := reader.ReadLine()
	if err != nil {
		conn.Write(codeIO)
		return nil, err
	}
	if isPrefix {
		conn.Write(codeIO)
		return nil, errBadRequest
	}
	if addr, err = aes256cbc.DecryptBase64(secret, base64); err != nil {
		conn.Write(codeBad)
		return nil, err
	}
	return
}

func dial(addr string, remoteAddr string) (net.Conn, error) {
	buf := make256(byte(len(remoteAddr) + 1))
	defer free256(buf)

	buf[0] = byte(len(remoteAddr))
	copy(buf[1:], remoteAddr)

	for i := 0; i < dialRetry; i++ {
		conn, err := net.DialTimeout("tcp", addr, dialTimeout)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return nil, err
		}
		// send client address to backend
		err = conn.SetWriteDeadline(time.Now().Add(dialTimeout))
		if err != nil {
			return nil, err
		}
		_, err = conn.Write(buf)
		if err != nil {
			return nil, err
		}
		err = conn.SetWriteDeadline(time.Time{})
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
	return nil, errDialTimeout
}

func safeCopy(dst io.Writer, src io.Reader) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("Unhandled panic in safe copy: %v\n\n%s", err, debug.Stack())
		}
	}()
	io.Copy(dst, src)
}

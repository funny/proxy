package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
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

	"github.com/funny/gateway/reuseport"
)

var (
	cfgSecret            []byte
	cfgDialRetry         = 1
	cfgDialTimeout       = 3 * time.Second
	cfgMaxHTTPHeaderSize = 8096

	codeOK          = []byte("200")
	codeBadReq      = []byte("400")
	codeBadAddr     = []byte("401")
	codeDialErr     = []byte("502")
	codeDialTimeout = []byte("504")

	httpHead         = []byte("HTTP")
	httpCipherOrigin = []byte("x-cipher-origin")
	httpForwardedFor = []byte("x-forwarded-for")

	errBadRequest = errors.New("Bad request")

	isTest      bool
	gatewayAddr string
	bufioPool   sync.Pool
	bufferPool  sync.Pool
)

func main() {
	pid := syscall.Getpid()
	if err := ioutil.WriteFile("gateway.pid", []byte(strconv.Itoa(pid)), 0644); err != nil {
		log.Fatalf("Can't write pid file: %s", err)
	}
	defer os.Remove("gateway.pid")

	config()
	gateway()

	sigTERM := make(chan os.Signal, 1)
	signal.Notify(sigTERM, syscall.SIGTERM)
	printf("Gateway running, pid = %d", pid)
	<-sigTERM
	printf("Gateway killed")
}

func fatal(t string) {
	if !isTest {
		log.Fatal(t)
	}
	panic(t)
}

func fatalf(t string, args ...interface{}) {
	if !isTest {
		log.Fatalf(t, args...)
	}
	panic(fmt.Sprintf(t, args...))
}

func printf(t string, args ...interface{}) {
	if !isTest {
		log.Printf(t, args...)
	}
}

func config() {
	if v := os.Getenv("GW_SECRET"); v != "" {
		cfgSecret = []byte(os.Getenv("GW_SECRET"))
		printf("GW_SECRET=%s", cfgSecret)
	} else {
		fatal("GW_SECRET is required")
	}

	var err error

	if v := os.Getenv("GW_DIAL_RETRY"); v != "" {
		cfgDialRetry, err = strconv.Atoi(v)
		if err != nil {
			fatalf("GW_DIAL_RETRY - %s", err)
		}
		if cfgDialRetry == 0 {
			cfgDialRetry = 1
		}
	}
	printf("GW_DIAL_RETRY=%d", cfgDialRetry)

	var timeout int
	if v := os.Getenv("GW_DIAL_TIMEOUT"); v != "" {
		timeout, err = strconv.Atoi(v)
		if err != nil {
			fatalf("GW_DIAL_TIMEOUT - %s", err)
		}
	}
	if timeout == 0 {
		timeout = 3
	}
	cfgDialTimeout = time.Duration(timeout) * time.Second
	printf("GW_DIAL_TIMEOUT=%d", timeout)

	if v := os.Getenv("GW_PPROF_ADDR"); v != "" {
		listener, err := net.Listen("tcp", v)
		if err != nil {
			fatalf("Setup pprof failed: %s", err)
		}
		printf("Setup pprof at %s", listener.Addr())
		go http.Serve(listener, nil)
	}
}

func gateway() {
	var err error
	var listener net.Listener

	port := os.Getenv("GW_PORT")
	if port == "" {
		port = "0"
	}

	if os.Getenv("GW_REUSE_PORT") == "1" {
		listener, err = reuseport.NewReusablePortListener("tcp4", "0.0.0.0:"+port)
	} else {
		listener, err = net.Listen("tcp", "0.0.0.0:"+port)
	}

	if err != nil {
		fatalf("Setup listener failed: %s", err)
	}

	gatewayAddr = listener.Addr().String()
	printf("Setup gateway at %s", gatewayAddr)
	go loop(listener)
}

func loop(listener net.Listener) {
	defer listener.Close()
	for {
		conn, err := accept(listener)
		if err != nil {
			fatalf("Gateway accept failed: %s", err)
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
		if conn != nil {
			conn.Close()
		}
		if err := recover(); err != nil {
			printf("Unhandled panic in connection handler: %v\n\n%s", err, debug.Stack())
		}
	}()

	released := false
	reader, ok := bufioPool.Get().(*bufio.Reader)
	if ok {
		reader.Reset(conn)
	} else {
		reader = bufio.NewReader(conn)
	}
	defer func() {
		if !released {
			reader.Reset(nil)
			bufioPool.Put(reader)
		}
	}()

	addr, header, isHTTP := handshake(conn, reader)
	if addr == nil {
		return
	}
	if header != nil {
		defer func() {
			if !released {
				header.Reset()
				bufferPool.Put(header)
			}
		}()
	}

	agent := dial(string(addr), conn, reader)
	if agent == nil {
		return
	}
	defer agent.Close()

	released = release(agent, conn, reader, header)
	if !released {
		conn.Write(codeDialErr)
		return
	}

	if !isHTTP {
		if _, err := conn.Write(codeOK); err != nil {
			return
		}
	}

	go safeCopy(conn, agent)
	io.Copy(agent, conn)
}

func dial(addr string, conn net.Conn, reader *bufio.Reader) net.Conn {
	for i := 0; i < cfgDialRetry; i++ {
		agent, err := net.DialTimeout("tcp", addr, cfgDialTimeout)
		if err == nil {
			return agent
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			continue
		}
		conn.Write(codeDialErr)
		return nil
	}
	conn.Write(codeDialTimeout)
	return nil
}

func release(agent, conn net.Conn, reader *bufio.Reader, header *bytes.Buffer) bool {
	hasHeader := header != nil && header.Len() > 0
	// Send bufio.Reader buffered data.
	if n := reader.Buffered(); n > 0 || hasHeader {
		err := agent.SetWriteDeadline(time.Now().Add(cfgDialTimeout))
		if err != nil {
			return false
		}
		if hasHeader {
			if _, err = agent.Write(header.Bytes()); err != nil {
				return false
			}
		}
		if n > 0 {
			var data []byte
			if data, err = reader.Peek(n); err != nil {
				return false
			}
			if _, err = agent.Write(data); err != nil {
				return false
			}
		}
		err = agent.SetWriteDeadline(time.Time{})
		if err != nil {
			return false
		}
	}
	// Release the reader.
	reader.Reset(nil)
	bufioPool.Put(reader)
	// Release the header.
	if header != nil {
		header.Reset()
		bufferPool.Put(header)
	}
	return true
}

func safeCopy(dst io.WriteCloser, src io.ReadCloser) {
	defer func() {
		if dst != nil {
			dst.Close()
		}
		if src != nil {
			src.Close()
		}
		if err := recover(); err != nil {
			printf("Unhandled panic in safe copy: %v\n\n%s", err, debug.Stack())
		}
	}()
	io.Copy(dst, src)
}

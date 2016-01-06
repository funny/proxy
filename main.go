package main

import (
	"bytes"
	"flag"
	"fmt"
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

	"github.com/funny/crypto/aes256cbc"
	"github.com/funny/reuseport"
)

const miniBufferSize = 1024

var (
	configed       = false
	cfgSecret      []byte
	cfgGatewayAddr = "0.0.0.0:0"
	cfgPprofAddr   = ""
	cfgReusePort   = false
	cfgDialRetry   = uint(1)
	cfgDialTimeout = uint(3)
	cfgBufferSize  = uint(16 * 1024)

	codeOK          = []byte("200")
	codeBadReq      = []byte("400")
	codeBadAddr     = []byte("401")
	codeDialErr     = []byte("502")
	codeDialTimeout = []byte("504")

	isTest     bool
	bufferPool sync.Pool
)

func init() {
	var secret string
	flag.StringVar(&secret, "secret", "", "The passphrase used to decrypt target server address")
	flag.StringVar(&cfgGatewayAddr, "addr", cfgGatewayAddr, "Network address for gateway")
	flag.StringVar(&cfgPprofAddr, "pprof", cfgPprofAddr, "Network address for net/http/pprof")
	flag.BoolVar(&cfgReusePort, "reuse", cfgReusePort, "Enable reuse port feature")
	flag.UintVar(&cfgDialRetry, "retry", cfgDialRetry, "Retry times when dial to target server timeout")
	flag.UintVar(&cfgDialTimeout, "timeout", cfgDialTimeout, "Timeout seconds when dial to targer server")
	flag.UintVar(&cfgBufferSize, "buffer", cfgBufferSize, "Buffer size for io.CopyBuffer()")
	flag.Parse()

	cfgSecret = []byte(secret)

	cfgDialTimeout = uint(time.Second) * cfgDialTimeout

	bufferPool.New = func() interface{} {
		return make([]byte, cfgBufferSize)
	}
}

func main() {
	if len(cfgSecret) == 0 {
		fatal("Missing passphrase")
		return
	}

	if cfgPprofAddr != "" {
		listener, err := net.Listen("tcp", cfgPprofAddr)
		if err != nil {
			fatalf("Setup pprof failed: %s", err)
		}
		printf("Setup pprof at %s", listener.Addr())
		go http.Serve(listener, nil)
	}

	pid := syscall.Getpid()
	if err := ioutil.WriteFile("gateway.pid", []byte(strconv.Itoa(pid)), 0644); err != nil {
		log.Fatalf("Can't write pid file: %s", err)
	}
	defer os.Remove("gateway.pid")

	start()

	printf("Gateway address: %s", cfgGatewayAddr)
	printf("Reuse port: %v", cfgReusePort)
	printf("Dial retry: %d", cfgDialRetry)
	printf("Dial timeout: %s", time.Duration(cfgDialTimeout))
	printf("Buffer size: %d", cfgBufferSize)
	printf("Passphrase: %s", cfgSecret)

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

func start() {
	var err error
	var listener net.Listener

	if cfgReusePort {
		listener, err = reuseport.NewReusablePortListener("tcp4", cfgGatewayAddr)
	} else {
		listener, err = net.Listen("tcp", cfgGatewayAddr)
	}
	if err != nil {
		fatalf("Setup listener failed: %s", err)
	}

	cfgGatewayAddr = listener.Addr().String()
	printf("Setup gateway at %s", cfgGatewayAddr)
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
		conn.Close()
		if err := recover(); err != nil {
			printf("Unhandled panic in connection handler: %v\n\n%s", err, debug.Stack())
		}
	}()

	agent := handshake(conn)
	if agent == nil {
		return
	}
	defer agent.Close()

	go func() {
		defer func() {
			agent.Close()
			conn.Close()
			if err := recover(); err != nil {
				printf("Unhandled panic in connection handler: %v\n\n%s", err, debug.Stack())
			}
		}()
		copy(conn, agent)
	}()
	copy(agent, conn)
}

func handshake(conn net.Conn) (agent net.Conn) {
	var addr []byte
	var remain []byte

	// read and decrypt target server address
	var buf [64]byte
	var err error
	for n, nn := 0, 0; n < len(buf); n += nn {
		nn, err = conn.Read(buf[n:])
		if err != nil {
			conn.Write(codeBadReq)
			return
		}
		if i := bytes.IndexByte(buf[n:n+nn], '\n'); i >= 0 {
			if addr, err = aes256cbc.DecryptBase64(cfgSecret, buf[:n+i]); err != nil {
				conn.Write(codeBadAddr)
				return nil
			}
			remain = buf[n+i+1 : n+nn]
			break
		}
	}
	if addr == nil {
		conn.Write(codeBadReq)
		return nil
	}

	// dial to target server
	for i := uint(0); i < cfgDialRetry; i++ {
		agent, err = net.DialTimeout("tcp", string(addr), time.Duration(cfgDialTimeout))
		if err == nil {
			break
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			continue
		}
		conn.Write(codeDialErr)
		return nil
	}
	if err != nil {
		conn.Write(codeDialTimeout)
		return nil
	}

	// send succeed code
	if _, err = conn.Write(codeOK); err != nil {
		agent.Close()
		return nil
	}

	// send remainder data in buffer
	if len(remain) > 0 {
		if _, err = agent.Write(remain); err != nil {
			agent.Close()
			return nil
		}
	}
	return
}

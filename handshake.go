package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"

	"github.com/funny/crypto/aes256cbc"
)

func handshake(conn net.Conn, reader *bufio.Reader) (addr []byte, header *bytes.Buffer, isHTTP bool) {
	firstByte, err := reader.ReadByte()
	if err != nil {
		conn.Write(codeBadReq)
		return
	}
	switch firstByte {
	case 0:
		addr, err = handshakeBinary(conn, reader)
		return
	default:
		if err = reader.UnreadByte(); err != nil {
			return
		}
		return handshakeText(conn, reader)
	}
}

func handshakeBinary(conn net.Conn, reader *bufio.Reader) (addr []byte, err error) {
	var n byte
	n, err = reader.ReadByte()
	if err != nil {
		conn.Write(codeBadReq)
		return nil, err
	}

	var buf [256]byte
	bin := buf[:n]
	if _, err = io.ReadFull(reader, bin); err != nil {
		conn.Write(codeBadReq)
		return nil, err
	}

	if addr, err = aes256cbc.Decrypt(cfgSecret, bin); err != nil {
		conn.Write(codeBadAddr)
		return nil, err
	}
	return
}

func handshakeText(conn net.Conn, reader *bufio.Reader) (addr []byte, header *bytes.Buffer, isHTTP bool) {
	head, err := reader.ReadSlice('\n')
	if err != nil {
		conn.Write(codeBadReq)
		return
	}
	if isHTTP = bytes.Contains(head, httpHead); isHTTP {
		addr, header = handshakeHTTP(conn, reader, head)
		return
	}
	if addr, err = aes256cbc.DecryptBase64(cfgSecret, head); err != nil {
		conn.Write(codeBadAddr)
		return
	}
	return
}

func handshakeHTTP(conn net.Conn, reader *bufio.Reader, firstLine []byte) ([]byte, *bytes.Buffer) {
	header, ok := bufferPool.Get().(*bytes.Buffer)
	if !ok {
		header = new(bytes.Buffer)
	}
	header.Write(firstLine)
	header.WriteByte('\n')

	var xff []byte
	var addr []byte
	for {
		line, err := reader.ReadSlice('\n')
		if err != nil {
			conn.Write(codeBadReq)
			return nil, nil
		}

		var allMatched bool

		// lookup X-Cipher-Origin
		if bytes.HasPrefix(bytes.ToLower(line), httpCipherOrigin) {
			addr = bytes.TrimSpace(line[len(httpCipherOrigin)+1:])
			if xff == nil {
				continue
			}
			allMatched = true
		}

		// lookup X-Forwarded-For
		if bytes.HasPrefix(bytes.ToLower(line), httpForwardedFor) {
			xff = bytes.TrimSpace(line[len(httpForwardedFor)+1:])
			if addr == nil {
				continue
			}
			allMatched = true
		}

		var isEnd bool

		if allMatched {
			goto END
		} else {
			// end of HTTP header
			isEnd = len(bytes.TrimSpace(line)) == 0
		}

	END:
		if isEnd || allMatched {
			if len(addr) == 0 {
				conn.Write(codeBadAddr)
				return nil, nil
			}
			header.WriteString("X-Forwarded-For: ")
			if len(xff) != 0 {
				header.Write(xff)
				header.WriteString(", ")
			}
			header.WriteString(ipAddrFromRemoteAddr(conn.RemoteAddr().String()))
			if isEnd {
				header.Write(line)
				header.Write([]byte("\n"))
			}
			break
		}

		header.Write(line)
		header.WriteByte('\n')

		if header.Len() > cfgMaxHTTPHeaderSize {
			conn.Write(codeBadReq)
			return nil, nil
		}
	}
	return addr, header
}

func ipAddrFromRemoteAddr(s string) string {
	idx := strings.LastIndex(s, ":")
	if idx == -1 {
		return s
	}
	return s[:idx]
}

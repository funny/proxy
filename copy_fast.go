// +build go1.5

package main

import "io"

func copy(dst io.WriteCloser, src io.ReadCloser) {
	b := copyBufPool.Get().(*[]byte)
	buf := *b
	io.CopyBuffer(dst, src, buf)
	copyBufPool.Put(b)
}

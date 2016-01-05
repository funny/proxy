// +build go1.5

package main

import "io"

func copy(dst io.WriteCloser, src io.ReadCloser) {
	buf := bufferPool.Get().([]byte)
	io.CopyBuffer(dst, src, buf)
	bufferPool.Put(buf)
}

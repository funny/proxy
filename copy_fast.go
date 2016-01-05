// +build go1.5

package main

import "io"

func copy(dst io.WriteCloser, src io.ReadCloser) {
	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)
	io.CopyBuffer(dst, src, buf)
}

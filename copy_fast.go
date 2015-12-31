// +build !go1.5

package main

import "io"

func copy(dst io.WriteCloser, src io.ReadCloser) {
	io.Copy(dst, src)
}

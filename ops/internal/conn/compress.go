package conn

import (
	"compress/gzip"
	"context"
	"io"
	"log"
	"net/http"
)

// gzipCompress implements Compressor to allow compressing requests to the server.
func gzipCompress(ctx context.Context, ct CallType, path string, headers http.Header, r io.Reader) (*http.Request, error) {
	pipeOut, pipeIn := io.Pipe()
	w := gzip.NewWriter(pipeIn)

	go func() {
		_, err := io.Copy(w, r)
		if err != nil {
			log.Println("error on gzipCompress(io.Copy()): ", err)
			pipeIn.CloseWithError(err)
			w.Close()
			return
		}
		if err := w.Close(); err != nil {
			log.Println("error on gzip.Writer.Close(): ", err)
			pipeIn.CloseWithError(err)
			return
		}
		pipeIn.Close()
	}()

	req, err := http.NewRequestWithContext(ctx, string(ct), path, pipeOut)
	if err != nil {
		log.Println("error creating new HTTP request: ", err)
		return nil, err
	}
	if headers != nil {
		req.Header = headers
	}
	req.Header.Add("Content-Encoding", "gzip")

	return req, nil
}

// gzipDecompress implements Decompressor for decompressing gzip content.
func gzipDecompress(r io.Reader) io.Reader {
	gzipReader, _ := gzip.NewReader(r)

	pipeOut, pipeIn := io.Pipe()
	go func() {
		_, err := io.Copy(pipeIn, gzipReader)
		if err != nil {
			pipeIn.CloseWithError(err)
			gzipReader.Close()
			return
		}
		if err := gzipReader.Close(); err != nil {
			pipeIn.CloseWithError(err)
			return
		}
		pipeIn.Close()
	}()
	return pipeOut
}

package localagent

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
)

// BaseURL is the (never resolved) address the in-process agent uses. The agent transport insists
// on https; nothing is sent over any network.
const BaseURL = "https://panoptes.local"

// loopbackAddr is the RemoteAddr the API handlers see, so IP limiters treat the local agent
// like any other loopback client.
const loopbackAddr = "127.0.0.1:0"

// maxResponse caps an in-memory response (the API answers with small JSON documents).
const maxResponse = 16 << 20

// HandlerTransport is an http.RoundTripper that dispatches requests straight to an
// http.Handler in the same process: every validation, limit and enrollment rule of the real
// agent API applies, and nothing touches the network.
type HandlerTransport struct {
	Handler http.Handler
}

// RoundTrip implements http.RoundTripper.
func (t HandlerTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	defer func() {
		if r := recover(); r != nil {
			resp, err = nil, fmt.Errorf("in-process API handler panicked: %v", r)
		}
	}()
	sreq := req.Clone(req.Context())
	sreq.RemoteAddr = loopbackAddr
	sreq.RequestURI = req.URL.RequestURI()
	sreq.Proto, sreq.ProtoMajor, sreq.ProtoMinor = "HTTP/1.1", 1, 1
	if sreq.Host == "" {
		sreq.Host = req.URL.Host
	}
	if sreq.Body == nil {
		sreq.Body = http.NoBody
	}
	rec := &recorder{header: http.Header{}, code: http.StatusOK}
	t.Handler.ServeHTTP(rec, sreq)
	if sreq.Body != nil {
		_ = sreq.Body.Close()
	}

	out := &http.Response{
		Status:     fmt.Sprintf("%d %s", rec.code, http.StatusText(rec.code)),
		StatusCode: rec.code,
		Proto:      "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header:  rec.header.Clone(),
		Request: req,
	}
	body := rec.buf.Bytes()
	// A real http.Transport transparently decodes gzip responses it asked for; do the same.
	if ce := out.Header.Get("Content-Encoding"); ce == "gzip" || ce == "x-gzip" {
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("in-process response: %w", err)
		}
		dec, err := io.ReadAll(io.LimitReader(zr, maxResponse+1))
		if err != nil {
			return nil, fmt.Errorf("in-process response: %w", err)
		}
		body = dec
		out.Header.Del("Content-Encoding")
		out.Uncompressed = true
	}
	out.Header.Del("Content-Length")
	out.ContentLength = int64(len(body))
	out.Body = io.NopCloser(bytes.NewReader(body))
	return out, nil
}

// recorder is a minimal buffering http.ResponseWriter (net/http/httptest is not linked into the
// server binary).
type recorder struct {
	header      http.Header
	code        int
	wroteHeader bool
	buf         bytes.Buffer
}

func (r *recorder) Header() http.Header { return r.header }

func (r *recorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.wroteHeader, r.code = true, code
}

func (r *recorder) Write(p []byte) (int, error) {
	r.WriteHeader(http.StatusOK)
	if r.buf.Len()+len(p) > maxResponse {
		return 0, fmt.Errorf("in-process response exceeds %d bytes", maxResponse)
	}
	return r.buf.Write(p)
}

// NewHTTPClient returns an http.Client that talks to h in memory.
func NewHTTPClient(h http.Handler) *http.Client {
	return &http.Client{Transport: HandlerTransport{Handler: h}}
}

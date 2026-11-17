package rulesbot

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Limits of the bulk export reader.
const (
	MaxBulkBytes    = 200 << 20 // download size cap per ecosystem file
	MaxEntryBytes   = 4 << 20   // one JSON entry
	maxBulkEntries  = 2_000_000
	maxBulkInflated = 6 << 30 // all entries together, after decompression
	bulkTimeout     = 15 * time.Minute
)

type cacheMeta struct {
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

// fetchBulk makes sure the cached OSV export of an ecosystem ("Debian", "Alpine") is current and
// returns its path. An unchanged export (HTTP 304 for If-None-Match / If-Modified-Since) is reused;
// when the download fails but an older copy is cached, that copy is used.
func fetchBulk(ctx context.Context, f *fetcher, base, eco, dir string, log *slog.Logger) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	dest := filepath.Join(dir, strings.NewReplacer("/", "_", " ", "_").Replace(eco)+".zip")
	u := strings.TrimRight(base, "/") + "/" + url.PathEscape(eco) + "/all.zip"
	_, statErr := os.Stat(dest)
	cached := statErr == nil
	status, err := f.download(ctx, u, dest, cached, MaxBulkBytes)
	switch {
	case err == nil && status == http.StatusNotModified:
		log.Info("bulk export up to date, using the cache", "ecosystem", eco)
	case err == nil:
		log.Info("bulk export downloaded", "ecosystem", eco)
	case cached && !errors.Is(err, ErrRequestCap):
		log.Warn("bulk export download failed, using the cached copy", "ecosystem", eco, "err", err)
	default:
		return "", err
	}
	return dest, nil
}

// download fetches u into dest. With useCache the validators saved next to dest are sent and an
// HTTP 304 leaves dest alone. The body is capped at max bytes. It counts as one request.
func (f *fetcher) download(ctx context.Context, u, dest string, useCache bool, max int64) (int, error) {
	if f.count >= f.max {
		return 0, ErrRequestCap
	}
	f.count++
	ctx, cancel := context.WithTimeout(ctx, bulkTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", UserAgent)
	var meta cacheMeta
	if useCache {
		if b, err := os.ReadFile(dest + ".meta"); err == nil {
			_ = json.Unmarshal(b, &meta)
		}
		if meta.ETag != "" {
			req.Header.Set("If-None-Match", meta.ETag)
		}
		if meta.LastModified != "" {
			req.Header.Set("If-Modified-Since", meta.LastModified)
		}
	}
	c := *f.c
	c.Timeout = 0 // the context bounds the download
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified && useCache && (meta.ETag != "" || meta.LastModified != "") {
		return resp.StatusCode, nil
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("%s: HTTP %d", redact(u), resp.StatusCode)
	}
	if resp.ContentLength > max {
		return resp.StatusCode, fmt.Errorf("%s: %d bytes exceed the limit of %d", redact(u), resp.ContentLength, max)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), filepath.Base(dest)+".tmp-*")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, max+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return 0, err
	}
	if n > max {
		return 0, fmt.Errorf("%s: download exceeds the limit of %d bytes", redact(u), max)
	}
	if err := os.Rename(tmp.Name(), dest); err != nil {
		return 0, err
	}
	mb, _ := json.Marshal(cacheMeta{ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")})
	_ = os.WriteFile(dest+".meta", mb, 0o644)
	return resp.StatusCode, nil
}

// scanZip streams the JSON entries of an OSV export through handle without extracting them to
// disk. Entries larger than MaxEntryBytes (declared or actual) and unreadable ones are skipped; the
// scan stops with an error when the archive holds too many entries or inflates beyond a sane size.
// It returns the number of records handled.
func scanZip(path string, handle func(*osvDetail)) (int, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return 0, err
	}
	defer zr.Close()
	if len(zr.File) > maxBulkEntries {
		return 0, fmt.Errorf("archive has %d entries (limit %d)", len(zr.File), maxBulkEntries)
	}
	var total int64
	handled := 0
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() || !strings.HasSuffix(zf.Name, ".json") || zf.UncompressedSize64 > MaxEntryBytes {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(rc, MaxEntryBytes+1))
		rc.Close()
		if err != nil || len(raw) > MaxEntryBytes {
			continue
		}
		if total += int64(len(raw)); total > maxBulkInflated {
			return handled, errors.New("archive inflates beyond the size limit")
		}
		var d osvDetail
		if json.Unmarshal(raw, &d) != nil {
			continue
		}
		handled++
		handle(&d)
	}
	return handled, nil
}

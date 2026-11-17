// Command fakeserver is a tiny stand-in for panoptes-server used by deploy/e2e/split-mode.sh.
// It accepts enroll, checkin and inventory requests and writes what it received to -out.
package main

import (
	"compress/gzip"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8099", "listen address")
	out := flag.String("out", "/tmp/fakeserver", "directory for received payloads")
	flag.Parse()
	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}
	save := func(name string, data []byte) {
		if err := os.WriteFile(filepath.Join(*out, name), data, 0o644); err != nil {
			log.Print(err)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		save("enroll.json", body)
		json.NewEncoder(w).Encode(map[string]string{"agent_id": "fake-agent", "agent_key": "fake-key"})
	})
	mux.HandleFunc("/api/v1/checkin", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fake-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		save("checkin.json", body)
		json.NewEncoder(w).Encode(map[string]any{"want_inventory": true})
	})
	mux.HandleFunc("/api/v1/inventory", func(w http.ResponseWriter, r *http.Request) {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(zr, 256<<20))
		save("inventory.json", body)
		w.WriteHeader(http.StatusAccepted)
	})
	log.Printf("fakeserver listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

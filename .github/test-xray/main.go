// Локальная заглушка API для интеграционного теста установщика, без VPN-трафика.
package main

import (
	"encoding/binary"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	var paths []string
	test := false
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-test":
			test = true
		case "-config":
			i++
			paths = []string{os.Args[i]}
		case "-confdir":
			i++
			paths, _ = filepath.Glob(filepath.Join(os.Args[i], "*.json"))
		}
	}
	c := map[string]any{}
	for _, p := range paths {
		b, e := os.ReadFile(p)
		if e != nil {
			os.Exit(2)
		}
		var part map[string]any
		if json.Unmarshal(b, &part) != nil {
			os.Exit(2)
		}
		for k, v := range part {
			c[k] = v
		}
	}
	if test {
		if c["fail_validation"] == true {
			os.Exit(3)
		}
		return
	}
	api, _ := c["api"].(map[string]any)
	address, _ := api["listen"].(string)
	if address == "" {
		for {time.Sleep(time.Hour)}
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	server := &http.Server{Addr: address, Protocols: protocols, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Grpc-Status", "0")
		w.Header().Set("Content-Type", "application/grpc")
		var body []byte
		if strings.HasSuffix(r.URL.Path, "/GetOutboundStatus") {
			status := []byte{8, 1, 16, 100, 34, 3, 'v', 'p', 'n', 40}
			status = binary.AppendUvarint(status, uint64(time.Now().Unix()))
			status = append(status, 48)
			status = binary.AppendUvarint(status, uint64(time.Now().Unix()))
			record := append([]byte{10, byte(len(status))}, status...)
			body = append([]byte{10, byte(len(record))}, record...)
		}
		frame := make([]byte, 5)
		binary.BigEndian.PutUint32(frame[1:], uint32(len(body)))
		_, _ = w.Write(append(frame, body...))
	})}
	if server.ListenAndServe() != nil {
		os.Exit(4)
	}
}

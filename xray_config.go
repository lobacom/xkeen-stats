package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Xray допускает комментарии в JSON. Строки (в том числе URL) сохраняются.
func uncommentJSON(b []byte) ([]byte, error) {
	out := append([]byte(nil), b...)
	quoted, escaped := false, false
	for i := 0; i < len(out); i++ {
		if quoted {
			if escaped {
				escaped = false
			} else if out[i] == '\\' {
				escaped = true
			} else if out[i] == '"' {
				quoted = false
			}
			continue
		}
		if out[i] == '"' {
			quoted = true
			continue
		}
		if out[i] != '/' || i+1 >= len(out) {
			continue
		}
		if out[i+1] == '/' {
			out[i] = ' '
			i++
			for i < len(out) && out[i] != '\n' {
				out[i] = ' '
				i++
			}
			continue
		}
		if out[i+1] == '*' {
			out[i] = ' '
			i++
			out[i] = ' '
			closed := false
			for i++; i < len(out); i++ {
				if out[i] == '*' && i+1 < len(out) && out[i+1] == '/' {
					out[i] = ' '
					i++
					out[i] = ' '
					closed = true
					break
				}
				if out[i] != '\n' {
					out[i] = ' '
				}
			}
			if !closed {
				return nil, errors.New("unterminated JSON comment")
			}
		}
	}
	return out, nil
}

func decodeXrayObject(b []byte) (jsonObject, error) {
	b, err := uncommentJSON(b)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var c jsonObject
	if err = d.Decode(&c); err != nil {
		return nil, err
	}
	if c == nil {
		return nil, errors.New("Xray config must be an object")
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return nil, errors.New("unexpected data after JSON object")
	}
	return c, nil
}

func xrayConfigFiles(path string) ([]string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return []string{path}, nil
	}
	files, err := filepath.Glob(filepath.Join(path, "*.json"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, errors.New("no .json files in Xray configuration directory")
	}
	return files, nil
}

func readXrayObjects(path string) (jsonObject, []string, error) {
	files, err := xrayConfigFiles(path)
	if err != nil {
		return nil, nil, err
	}
	merged := jsonObject{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, nil, err
		}
		if len(b) > 16<<20 {
			return nil, nil, errors.New("Xray config too large")
		}
		c, err := decodeXrayObject(b)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot parse %s: %w", f, err)
		}
		for key, value := range c {
			if key != "inbounds" && key != "outbounds" {
				merged[key] = value
				continue
			}
			entries := array(merged[key])
			var additions []any
			for _, v := range array(value) {
				tag := str(object(v)["tag"])
				found := false
				for i, old := range entries {
					if tag != "" && str(object(old)["tag"]) == tag {
						entries[i] = v
						found = true
						break
					}
				}
				if !found {
					additions = append(additions, v)
				}
			}
			if key == "outbounds" && !strings.Contains(strings.ToLower(filepath.Base(f)), "tail") {
				entries = append(additions, entries...)
			} else {
				entries = append(entries, additions...)
			}
			merged[key] = entries
		}
	}
	return merged, files, nil
}

func readXrayView(path string) ([]byte, error) {
	files, err := xrayConfigFiles(path)
	if err != nil {
		return nil, err
	}
	if len(files) == 1 {
		b, err := os.ReadFile(files[0])
		if err != nil {
			return nil, err
		}
		return uncommentJSON(b)
	}
	c, _, err := readXrayObjects(path)
	if err != nil {
		return nil, err
	}
	return json.Marshal(c)
}

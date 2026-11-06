package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// LoadDotEnv loads a .env file without overwriting variables already present in
// the process environment. It searches the working directory and nearby parents
// so both `go run ./cmd/server` from apps/api and repo-root commands work.
func LoadDotEnv() {
	seen := map[string]bool{}
	for _, candidate := range []string{".env", "../.env", "../../.env", "../../../.env"} {
		path, err := filepath.Abs(candidate)
		if err != nil || seen[path] {
			continue
		}
		seen[path] = true
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			line = strings.TrimPrefix(line, "export ")
			eq := strings.IndexByte(line, '=')
			if eq <= 0 {
				continue
			}
			key := strings.TrimSpace(line[:eq])
			val := strings.TrimSpace(line[eq+1:])
			if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'')) {
				val = val[1 : len(val)-1]
			}
			if _, exists := os.LookupEnv(key); !exists {
				_ = os.Setenv(key, val)
			}
		}
		f.Close()
		return
	}
}

package activate

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// pureProtocolRoot locates the vendored adobe_pure_protocol tree.
// Order: ADOBE_PURE_PROTOCOL env → DATA_DIR/activate/... → ./data/activate/...
// Never falls back to a machine-specific absolute path.
func pureProtocolRoot() string {
	cands := make([]string, 0, 6)
	if v := strings.TrimSpace(os.Getenv("ADOBE_PURE_PROTOCOL")); v != "" {
		cands = append(cands, v)
	}
	if dd := strings.TrimSpace(os.Getenv("DATA_DIR")); dd != "" {
		cands = append(cands, filepath.Join(dd, "activate", "adobe_pure_protocol"))
	}
	cands = append(cands,
		filepath.Join("data", "activate", "adobe_pure_protocol"),
		filepath.Join(".", "data", "activate", "adobe_pure_protocol"),
	)
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			if abs, err := filepath.Abs(c); err == nil {
				return abs
			}
			return c
		}
	}
	return ""
}

// pythonBin picks python3 on Unix, python on Windows, honoring PYTHON_BIN.
func pythonBin() string {
	if v := strings.TrimSpace(os.Getenv("PYTHON_BIN")); v != "" {
		return v
	}
	if path, err := exec.LookPath("python3"); err == nil && path != "" {
		return path
	}
	if path, err := exec.LookPath("python"); err == nil && path != "" {
		return path
	}
	return "python3"
}

// shellQuote wraps a path for the POW_SOLVER command line (node execSync runs
// it through a shell, so a path with spaces must stay one token).
func shellQuote(p string) string {
	if strings.ContainsAny(p, " \t") {
		return `"` + p + `"`
	}
	return p
}

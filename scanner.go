package injector

import (
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"time"
)

const defaultMinNumCaves = 350

// ScanOptions contains the scan options.
type ScanOptions struct {
	MinNumCaves  int  `json:"min_num_caves"`
	NoSignature  bool `json:"no_signature"`
	NoLoadConfig bool `json:"no_load_config"`
	IgnoreRank   bool `json:"ignore_rank"`
}

// ScanResult contain the scan image result.
type ScanResult struct {
	Path string       `json:"path"`
	Info *AnalyzeInfo `json:"info"`
}

// Scan is used to scan the target image in directory.
func Scan(path string, opts *ScanOptions) ([]*ScanResult, error) {
	if opts == nil {
		opts = new(ScanOptions)
	}
	rd := rand.New(rand.NewSource(time.Now().UnixNano())) // #nosec
	var results []*ScanResult
	err := filepath.Walk(path, func(path string, file os.FileInfo, _ error) error {
		if file.IsDir() {
			return nil
		}
		ext := filepath.Ext(file.Name())
		if ext == ".sys" {
			return nil
		}
		path, _ = filepath.Abs(path)
		if path == "" {
			return nil
		}
		if !maybePEImage(rd, path) {
			return nil
		}
		image, err := os.ReadFile(path) // #nosec
		if err != nil {
			return nil
		}
		info, err := Analyze(image)
		if err != nil {
			return nil
		}
		if !matchPEImage(info, opts) {
			return nil
		}
		results = append(results, &ScanResult{
			Path: path,
			Info: info,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}

func matchPEImage(info *AnalyzeInfo, opts *ScanOptions) bool {
	minNumCaves := opts.MinNumCaves
	if minNumCaves < 1 {
		minNumCaves = defaultMinNumCaves
	}
	if info.NumCodeCaves < minNumCaves {
		return false
	}
	if opts.NoSignature && info.HasSignature {
		return false
	}
	if opts.NoLoadConfig && info.HasLoadConfig {
		return false
	}
	if !opts.IgnoreRank {
		if !info.CanCreateSection && !info.CanInjectLoader {
			return false
		}
	}
	return true
}

func maybePEImage(rd *rand.Rand, path string) bool {
	f, err := os.Open(path) // #nosec
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 4+rd.Intn(64))
	_, err = io.ReadFull(f, buf)
	if err != nil {
		return false
	}
	if buf[0] == 'M' && buf[1] == 'Z' {
		return true
	}
	return false
}

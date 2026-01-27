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
	minNumCaves := opts.MinNumCaves
	if minNumCaves < 1 {
		minNumCaves = defaultMinNumCaves
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
		maybePE, err := maybePEImage(rd, path)
		if !maybePE || err != nil {
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
		// check condition in options
		if info.NumCodeCaves < opts.MinNumCaves {
			return nil
		}
		if opts.NoSignature && info.HasSignature {
			return nil
		}
		if opts.NoLoadConfig && info.HasLoadConfig {
			return nil
		}
		if !opts.IgnoreRank {
			if !info.CanCreateSection && !info.CanInjectLoader {
				return nil
			}
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

func maybePEImage(rd *rand.Rand, path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 4+rd.Intn(64))
	_, err = io.ReadFull(f, buf)
	if err != nil {
		return false, err
	}
	if buf[0] == 'M' && buf[1] == 'Z' {
		return true, nil
	}
	return false, nil
}

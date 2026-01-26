package injector

import (
	"os"
	"path/filepath"
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
		opts = &ScanOptions{
			MinNumCaves: defaultMinNumCaves,
		}
	}
	var results []*ScanResult
	err := filepath.Walk(path, func(path string, file os.FileInfo, _ error) error {
		if file.IsDir() {
			return nil
		}
		ext := filepath.Ext(file.Name())
		if ext != ".exe" && ext != ".dll" {
			return nil
		}
		path, _ = filepath.Abs(path)
		if path == "" {
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
		// check condition
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

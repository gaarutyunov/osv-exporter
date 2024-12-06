package filter

import (
	"context"
	"github.com/bluekeyes/go-gitdiff/gitdiff"
	"github.com/gaarutyunov/osv-exporter/osv"
)

// File filters out files depending on some conditions
type File interface {
	// Filter returns true if the file should be skipped
	Filter(ctx context.Context, file *gitdiff.File) (bool, error)
}

// Vulnerability filters vulnerabilities based on some conditions
type Vulnerability interface {
	Filter(ctx context.Context, vulnerability *osv.Vulnerability) (bool, error)
}

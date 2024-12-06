package exporter

import (
	"context"
	"github.com/bluekeyes/go-gitdiff/gitdiff"
	"github.com/gaarutyunov/osv-exporter/osv"
	"github.com/gaarutyunov/osv-exporter/vcs"
)

// File exports a file with potential vulnerability in some format
type File interface {
	// Export exports the file taking into account the vulnerability and changes to the original file into outDir
	Export(ctx context.Context, vulnerability *osv.Vulnerability, outDir string, file vcs.File, changes *gitdiff.File) error
}

package main

import (
	"bytes"
	"github.com/gaarutyunov/osv-exporter/exporter"
	"github.com/stretchr/testify/assert"
	"path/filepath"
	"testing"
)

func TestExport(t *testing.T) {
	var out, outErr bytes.Buffer

	cmd.SetOut(&out)
	cmd.SetErr(&outErr)

	outDir := t.TempDir()

	cmd.SetArgs([]string{
		"export",
		"--out",
		outDir,
		"--prefix",
		"PyPI/GHSA-795c-9xpc-xw6g",
		"--extension",
		".py",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	outDir = exporter.MetaExporterPath(
		outDir,
		"django",
		"django",
		"27900fe56f3d3cabb4aeb6ccb82f92bab29073a8",
		"django/utils/html.py",
	)

	assert.FileExists(t, filepath.Join(outDir, "meta.json"))
	assert.FileExists(t, filepath.Join(outDir, "new.py"))
	assert.FileExists(t, filepath.Join(outDir, "old.py"))
}

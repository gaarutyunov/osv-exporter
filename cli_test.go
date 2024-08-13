package main

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"net/url"
	"path/filepath"
	"testing"
)

func TestCLIAll(t *testing.T) {
	var out, outErr bytes.Buffer

	cmd.SetOut(&out)
	cmd.SetErr(&outErr)

	outDir := t.TempDir()

	cmd.SetArgs([]string{
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

	outDir = filepath.Join(outDir, "django.django", "7b7b909579c8311c140c89b8a9431bf537febf93", url.QueryEscape("django/utils/html.py"))

	assert.FileExists(t, filepath.Join(outDir, "meta.json"))
	assert.FileExists(t, filepath.Join(outDir, "new.py"))
	assert.FileExists(t, filepath.Join(outDir, "old.py"))
}

package main

import (
	"bytes"
	"context"
	"github.com/gaarutyunov/ovs-exporter/joern"
	"github.com/stretchr/testify/assert"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

	outDir = filepath.Join(outDir, "django.django", "7b7b909579c8311c140c89b8a9431bf537febf93", url.QueryEscape("django/utils/html.py"))

	assert.FileExists(t, filepath.Join(outDir, "meta.json"))
	assert.FileExists(t, filepath.Join(outDir, "new.py"))
	assert.FileExists(t, filepath.Join(outDir, "old.py"))
}

func TestImport(t *testing.T) {
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
		"--fail",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	loggingDir := t.TempDir()
	loggingFile := filepath.Join(loggingDir, "import.log")
	_, err := os.Create(loggingFile)
	if err != nil {
		t.Fatal(err)
	}

	cmd.SetArgs([]string{
		"import",
		"--in",
		outDir,
		"--logging",
		loggingFile,
		"--insecure",
	})

	joernServerCmd := exec.Command("joern", "--server")

	joernServerCmd.Stdout = &out
	joernServerCmd.Stderr = &outErr
	joernServerCmd.Dir = outDir

	err = joernServerCmd.Start()
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		err := joernServerCmd.Process.Signal(os.Interrupt)
		if err != nil {
			t.Fatal(err)
		}
	})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	client := joern.NewClient(joernServer, "", "")

	ctx := context.Background()

	err = client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}

	defer client.Close(ctx)

	message, err := client.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, joern.Connected, message)

	projectNames := make([]string, 0)

	glob, err := filepath.Glob(filepath.Join(outDir, "django.django", "*", "*"))
	if err != nil {
		t.Fatal(err)
	}

	for _, s := range glob {
		rel, err := filepath.Rel(outDir, s)
		if err != nil {
			t.Fatal(err)
		}
		projectNames = append(projectNames, strings.ReplaceAll(rel, string(filepath.Separator), "."))
	}

	for _, projectName := range projectNames {
		send, err := client.Send(ctx, "delete(\""+projectName+"\")")
		if err != nil {
			t.Fatal(err)
		}

		m, err := client.Receive(ctx)
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, send.UUID.String(), m)

		result, err := client.Result(ctx, send.UUID)
		if err != nil {
			t.Fatal(err)
		}

		assert.True(t, result.Success)
	}
}

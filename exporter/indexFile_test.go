package exporter

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bluekeyes/go-gitdiff/gitdiff"
	"github.com/gaarutyunov/osv-exporter/vcs"
	"github.com/google/go-github/v63/github"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestIndexFileExporter(t *testing.T) {
	client := github.NewClient(nil).WithAuthToken(os.Getenv("GITHUB_TOKEN"))

	ctx := context.Background()

	err := vcs.UpdateRateLimit(ctx, client, true)
	if err != nil {
		t.Fatal(err)
	}

	repo := vcs.NewRepository(client.Repositories, "django", "django")

	outDir := t.TempDir()

	const vulnURL = "https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2024/08/GHSA-pv4p-cwwg-4rph/GHSA-pv4p-cwwg-4rph.json"

	vuln, err := getVulnerability(vulnURL)
	if err != nil {
		t.Fatalf("Error getting vulnerability: %v", err)
	}

	const filePath = "django/db/models/sql/query.py"
	const sha = "32ebcbf2e1fe3e5ba79a6554a167efce81f7422d"

	prevCommit, err := repo.GetPreviousCommit(ctx, sha)
	if err != nil {
		t.Fatalf("repo.GetPreviousCommit(%q): %v", sha, err)
	}

	oldFile, err := repo.DownloadFileContents(ctx, prevCommit.GetSHA(), filePath)
	if err != nil {
		t.Fatalf("DownloadFileContents(%q, %q): %v", sha, filePath, err)
	}

	changes, err := repo.GetCommitChanges(ctx, sha, github.Diff)
	if err != nil {
		t.Fatalf("GetCommitChanges(%q): %v", sha, err)
	}
	files := changes.GetFiles()
	var file *gitdiff.File
	for _, p := range files {
		if p.OldName == filePath {
			file = p
		}
	}

	if file == nil {
		t.Fatalf("%q file not found", filePath)
	}
	str := uuid.NewString()
	exporter := IndexFileT(str)

	err = exporter.Export(ctx, vuln, outDir, oldFile, file)
	if err != nil {
		t.Fatalf("Export(%q, %q): %v", sha, filePath, err)
	}
	indexpath := outDir
	outDir = IndexFileExporterPath(
		outDir,
		filepath.Ext(file.OldName),
	)

	assert.FileExists(t, filepath.Join(outDir, str+filepath.Ext(file.OldName)))
	assert.FileExists(t, filepath.Join(indexpath, "index.jsonl"))

	metaRaw, err := os.ReadFile(filepath.Join(indexpath, "index.jsonl"))
	if err != nil {
		t.Fatalf("os.ReadFile(%q): %v", filePath, err)
	}

	var rec IndexFileContent

	err = json.Unmarshal(metaRaw, &rec)
	if err != nil {
		t.Fatalf("json.Unmarshal(%q): %v", filePath, err)
	}

	assert.Empty(t, rec.BadLines)
	assert.Equal(t, []int64{2449, 2450}, rec.GoodLines)

}

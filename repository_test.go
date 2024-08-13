package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"github.com/bluekeyes/go-gitdiff/gitdiff"
	"github.com/google/go-github/v63/github"
	"github.com/stretchr/testify/assert"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func getVulnerability(url string) (*Vulnerability, error) {
	var vuln Vulnerability

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	err = json.NewDecoder(resp.Body).Decode(&vuln)
	if err != nil {
		return nil, err
	}

	return &vuln, nil
}

func TestRepositoryAll(t *testing.T) {
	client := github.NewClient(nil).WithAuthToken(os.Getenv("GITHUB_TOKEN"))

	ctx := context.Background()

	err := UpdateRateLimit(ctx, client, true)
	if err != nil {
		t.Fatal(err)
	}

	repo := newRepository(client.Repositories, "django", "django")

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

	err = repo.ExportChanges(ctx, vuln, outDir, oldFile, file)
	if err != nil {
		t.Fatalf("ExportChanges(%q, %q): %v", sha, filePath, err)
	}

	assert.FileExists(t, filepath.Join(outDir, "meta.json"))
	assert.FileExists(t, filepath.Join(outDir, "old.py"))
	assert.FileExists(t, filepath.Join(outDir, "new.py"))

	metaRaw, err := os.ReadFile(filepath.Join(outDir, "meta.json"))
	if err != nil {
		t.Fatalf("os.ReadFile(%q): %v", filePath, err)
	}

	var meta Meta

	err = json.Unmarshal(metaRaw, &meta)
	if err != nil {
		t.Fatalf("json.Unmarshal(%q): %v", filePath, err)
	}

	assert.Empty(t, meta.BadLines)
	assert.Equal(t, []int64{2449, 2450}, meta.GoodLines)

	newRaw, err := os.ReadFile(filepath.Join(outDir, "new.py"))
	if err != nil {
		t.Fatalf("os.ReadFile(%q): %v", filePath, err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(newRaw))

	var i int64

	goodLines := map[int64]string{
		2449: "for field in fields:",
		2450: "self.check_alias(field)",
	}

	for scanner.Scan() {
		line := scanner.Text()
		i += 1

		for _, goodLine := range meta.GoodLines {
			if i == goodLine {
				assert.Contains(t, line, goodLines[goodLine])
			}
		}
	}
}
